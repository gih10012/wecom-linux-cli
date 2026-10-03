"""Replay-safe normal WeCom UI controls; no guessed VoIP-engine ABI.

Native mutations run on the validated client's UI thread. A journal is durable
before each invitation, acceptance, or hangup. Unknown outcomes are queried,
never submitted again. Caller identity in an incoming caption is not a native ID.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time

from . import audio, client, sending
from .messages import account
from .state import private_root, read_private

LIBRARIES = {
    'DuiLib.dll': '78759331b2e25fbb2f66f4a8a11c8df8731df09925769c3264de77ea3cec4055',
    'owl.dll': '8d03ca36a5adc9f730f2c8750cff70c35c3391806bc3fda3591bb3244ab35b51',
}
UNKNOWN = {'prepared', 'invitation_unknown', 'accept_unknown', 'hangup_unknown'}


def journal(request_id):
    if not sending.REQUEST.fullmatch(request_id):
        raise ValueError('INVALID_CALL_REQUEST_ID')
    return sending._folder(private_root() / 'calls') / (request_id + '.json')


@contextmanager
def lock():
    folder = sending._folder(private_root() / 'calls')
    fd = os.open(folder / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('UNSAFE_CALL_LOCK')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise ValueError('CALL_OPERATION_BUSY') from None
    finally:
        os.close(fd)


@contextmanager
def desktop_session():
    helper = Path.home() / '.local/share/niri-computer-use/bin/niri-desktop-session.py'
    if not helper.is_file():
        raise ValueError('NIRI_DESKTOP_SESSION_HELPER_REQUIRED')
    def invoke(action):
        result = subprocess.run(['/usr/bin/python3', str(helper), action,
                                 '--owner-pid', str(os.getpid())], capture_output=True,
                                text=True, timeout=5)
        value = json.loads(result.stdout)
        if result.returncode or not value.get('ok'):
            raise ValueError('CALL_DISPLAY_SESSION_' + action.upper() + '_FAILED')
        return value
    before = invoke('status')
    if before.get('session'):
        raise ValueError('CALL_DISPLAY_SESSION_BUSY')
    invoke('begin')
    try:
        invoke('wake')
        yield
    finally:
        invoke('end')


def artifacts():
    source = Path(__file__).parent / '_native'
    files = ('call_hook.c', 'call_probe.c', 'message_hook.h')
    digest = hashlib.sha256(b'normal-private-call-v1\0' + b''.join(
        (source / name).read_bytes() for name in files)).hexdigest()
    folder = sending._folder(private_root() / 'native' / digest)
    compiler = shutil.which('i686-w64-mingw32-gcc')
    result = {'digest': digest}
    for name, suffix, flags in (('call_hook', '.dll', ['-shared', '-Wl,--kill-at']),
                                ('call_probe', '.exe', ['-municode'])):
        target = folder / (name + suffix)
        if not target.exists():
            if not compiler:
                raise ValueError('MINGW32_COMPILER_REQUIRED')
            fd, temporary = tempfile.mkstemp(dir=folder, suffix=suffix)
            os.close(fd)
            try:
                built = subprocess.run([compiler, '-O2', '-Wall', '-Wextra', '-Werror',
                                        *flags, str(source / (name + '.c')), '-luser32',
                                        '-o', temporary], capture_output=True, timeout=60)
                if built.returncode:
                    raise ValueError('NATIVE_CALL_BUILD_FAILED_' + name.upper())
                Path(temporary).chmod(0o700)
                os.replace(temporary, target)
            finally:
                Path(temporary).unlink(missing_ok=True)
        info = target.lstat()
        if target.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('UNSAFE_CALL_ARTIFACT')
        result[name] = target
    return result


def context(name, chat=None):
    value = account(name)
    prepared = sending._prepare(name, chat or 'S:' + value['self_id'] + '_' + value['self_id'],
                                'normal voice call control')
    version = client.config().get('version')
    if version != '5.0.11.6018':
        raise ValueError('UNSUPPORTED_CALL_CLIENT_VERSION')
    for filename, expected in LIBRARIES.items():
        with (prepared['executable'].parent / version / filename).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                raise ValueError('UNSUPPORTED_CALL_LIBRARY_' + filename)
    built = artifacts()
    prepared['built'] = dict(prepared['built'], message_hook=built['call_hook'])
    prepared['call_built'] = built
    prepared.update(input_kind=0, width=0, height=0)
    return prepared


def probe(prepared, chat='-'):
    p = prepared['probe']
    result = subprocess.run([prepared['wine'], str(prepared['call_built']['call_probe']),
                             str(p['windows_pid']), str(p['creation_filetime']),
                             prepared['windows_exe'], chat, prepared['resolution']['hwnd']],
                            env=prepared['env'], capture_output=True, text=True, timeout=16)
    if len(result.stdout) > 65536:
        raise ValueError('CALL_PROBE_RESULT_TOO_LARGE')
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    if (result.returncode or not rows or not rows[-1].get('identity_unchanged') or
            client.processes(prepared['prefix'], prepared['executable']) != prepared['before']):
        raise ValueError('CALL_PROBE_IDENTITY_NOT_VERIFIED')
    return rows


def dispatch(prepared, mode, operation=0, window=None, payload=b'', caption=None):
    request = dict(prepared, input_kind=operation, payload=payload)
    if window:
        request['height'] = int(window['hwnd'], 16)
    if caption is not None:
        request['text'] = caption
    native, body = sending._dispatch(request, mode)
    result = json.loads(body) if body else None
    native['native_action_entered'] = native.pop('native_send_entered', False)
    native['native_action_returned'] = native.pop('send_returned', False)
    return native, result


def classify(prepared, window, tree):
    if not tree or not tree.get('complete') or tree.get('window_root') != window['root']:
        raise ValueError('COMPLETE_CALL_WINDOW_SNAPSHOT_REQUIRED')
    nodes = tree.get('nodes', [])
    def label(name):
        matches = [n['text'] for n in nodes if n.get('name') == name]
        return matches[0] if len(matches) == 1 else None
    handle = dict(windows_pid=prepared['probe']['windows_pid'],
                  creation_filetime=prepared['probe']['creation_filetime'],
                  hwnd=window['hwnd'], root=window['root'])
    if (window['kind'] == 'possible_invitation' and tree.get('accept_count') == 1 and
            label('single_voip_tips') == '邀请你语音通话' and label('inviter_name') and
            sum(n.get('name') == 'reject_btn' for n in nodes) == 1):
        descriptor = dict(handle, accept_button=tree['accept_button'],
                          caption=label('inviter_name'), account_scope=prepared['value']['scope'])
        token = hashlib.sha256(json.dumps(descriptor, sort_keys=True,
                                         ensure_ascii=False).encode()).hexdigest()
        return dict(kind='incoming', descriptor=descriptor, invitation_token=token,
                    caller_identity_verified=False, read_only=True)
    if window['kind'] != 'voice':
        return None
    tips, timer, peer = label('middle_tips'), label('titletext'), label('avatar_name')
    # middle_tips is a transient notification: it disappears after acceptance.
    # The private call's elapsed clock and typed hangup control remain visible.
    # A calling/ended tip, duplicate label, group layout, or invalid clock never
    # authorizes playback, even if an unrelated capture stream already exists.
    hangup_verified = tree.get('outer_count') == tree.get('inner_count') == 1
    tips_count = sum(n.get('name') == 'middle_tips' for n in nodes)
    connected = (tips_count <= 1 and tips in (None, '', '已接通') and
                 isinstance(timer, str) and re.fullmatch(r'\d{2,3}:[0-5]\d', timer) is not None
                 and bool(peer) and hangup_verified)
    ended = tips in ('已挂断', '通话结束', '对方已挂断', '已取消', '对方未接听')
    state = 'ended' if ended else 'connected' if connected else 'calling'
    return dict(kind='private' if peer is not None else 'group_unverified',
                handle=handle, state=state, timer=timer, peer_caption=peer, tips=tips,
                call_connection_verified=connected,
                binding=dict(root=tree['window_root'], outer=tree.get('hang_outer'),
                             inner=tree.get('hang_inner')),
                hangup_control_verified=hangup_verified)


def observe(prepared):
    incoming, active, ended = [], [], []
    for window in probe(prepared):
        if 'hwnd' not in window or window['tid'] != prepared['resolution']['tid']:
            continue
        native, tree = dispatch(prepared, 1, window=window)
        if not native.get('ok'):
            raise ValueError('CALL_WINDOW_READ_FAILED_' + str(native.get('failure')))
        item = classify(prepared, window, tree)
        if not item:
            continue
        if item['kind'] == 'incoming':
            incoming.append(item)
        elif item['state'] == 'ended':
            ended.append(item)
        else:
            active.append(item)
    if len(active) > 1:
        raise ValueError('MULTIPLE_ACTIVE_CALL_WINDOWS')
    return dict(ok=True, read_only=True, transport='normal_duilib_ui_thread',
                incoming=incoming, active=active[0] if active else None, ended=ended,
                call_connection_verified=bool(active and active[0]['call_connection_verified']))


def inspect(name='me'):
    with sending._lock():
        return observe(context(name))


def warm(prepared):
    native, result = dispatch(prepared, 1, operation=4)
    if not native.get('ok') or not result or result.get('system_modules_resolved') != 19:
        raise ValueError('CALL_SYSTEM_LIBRARY_WARMUP_FAILED')
    return result


def preflight(name='me', chat=None):
    with sending._lock():
        prepared = context(name, chat)
        warmed = warm(prepared)
        result = observe(prepared)
        result.update(read_only=False, local_system_library_warmup=warmed,
                      invitation_performed=False, native_voice_api_used=False)
        if chat:
            prepared = prepare_start(prepared)
            native, body = dispatch(prepared, 1, operation=2)
            result.update(ok=bool(native.get('ok')), target_preflight=body, native=native)
        return result


def prepare_start(prepared):
    if not re.fullmatch(r'S:\d+_\d+', prepared['chat']):
        raise ValueError('PRIVATE_CALL_CHAT_REQUIRED_GROUP_INVITATIONS_NOT_IMPLEMENTED')
    rows = probe(prepared, prepared['chat'])
    views = [r for r in rows if r.get('exact_requested_chat_matches')]
    if len(views) != 1 or not rows[-1].get('scan_complete'):
        raise ValueError('ONE_CACHED_ATTACHED_CHAT_VIEW_REQUIRED_OPEN_TARGET_IN_CLIENT')
    return dict(prepared, width=int(views[0]['view'], 16),
                height=int(prepared['resolution']['hwnd'], 16))


def handle_matches(record, live):
    return live is not None and record.get('handle') == live.get('handle')


def refresh(record, prepared):
    if prepared['value']['scope'] != record['account_scope']:
        raise ValueError('CALL_ACCOUNT_CHANGED')
    if prepared['before'][0] != record['process']:
        if process_alive(record):
            raise ValueError('ORIGINAL_CALL_CLIENT_STILL_RUNNING')
        return dict(record, status='ended', client_process_ended=True,
                    call_connection_verified=False, read_only=True)
    live = observe(prepared)
    matched = handle_matches(record, live['active'])
    result = dict(record, live=live, current_call_matches=matched,
                  call_connection_verified=bool(matched and live['call_connection_verified']), read_only=True)
    if matched:
        result['current_state'] = live['active']['state']
    elif record.get('handle'):
        result.update(status='ended', ended_observed=True, current_state=None)
    return result


def process_alive(record):
    try:
        return audio.process_start(record['process']['pid']) == record['process']['start_time']
    except (OSError, ValueError):
        return False


def status(request_id):
    with lock(), sending._lock():
        path = journal(request_id)
        if not path.is_file():
            raise ValueError('CALL_REQUEST_NOT_FOUND')
        record = read_private(path)
        if record['status'] in ('ended', 'failed_no_invitation', 'failed_no_accept'):
            return dict(record, read_only=True)
        if not process_alive(record):
            record.update(status='ended', client_process_ended=True, call_connection_verified=False)
            sending._persist(path, record)
            return dict(record, read_only=True)
        prepared = context(record['account'])
        record = refresh(record, prepared)
        sending._persist(path, record)
        return record


def block_unresolved(prepared):
    for path in journal('scan-only').parent.glob('*.json'):
        record = read_private(path)
        if record.get('account_scope') != prepared['value']['scope']:
            continue
        if record.get('status') in UNKNOWN:
            raise ValueError('CALL_OUTCOME_UNKNOWN_QUERY_OR_RESOLVE_ORIGINAL_REQUEST')
        if record.get('status') == 'active':
            record = refresh(record, prepared)
            sending._persist(path, record)
            if record['status'] != 'ended':
                raise ValueError('CALL_ALREADY_ACTIVE')


def replay(path, intent):
    if path.is_file():
        record = read_private(path)
        if record.get('intent') != intent:
            raise ValueError('CALL_REQUEST_ID_PAYLOAD_CONFLICT')
        return dict(record, replayed=True, read_only=True)
    return None


def wait_active(prepared, previous):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        live = observe(prepared)
        active = live['active']
        if active and active['handle'] != previous:
            return active
        time.sleep(.1)
    raise ValueError('CALL_WINDOW_NOT_OBSERVED_RESULT_UNKNOWN')


def start(name, chat, request_id):
    intent = dict(operation='start', account=name, chat=chat)
    with lock(), sending._lock():
        path = journal(request_id)
        old = replay(path, intent)
        if old:
            return old
        prepared = prepare_start(context(name, chat))
        block_unresolved(prepared)
        before = observe(prepared)
        if before['active'] or before['incoming']:
            raise ValueError('CALL_ALREADY_ACTIVE_OR_INCOMING')
        warm(prepared)
        checked, _ = dispatch(prepared, 1, operation=2)
        if not checked.get('ok'):
            return dict(ok=False, code='CALL_TARGET_PREFLIGHT_FAILED', native=checked,
                        invitation_performed=False, automatic_retry_allowed=False)
        record = dict(request_id=request_id, account=name, account_scope=prepared['value']['scope'],
                      chat_id=prepared['chat'], process=prepared['before'][0], intent=intent,
                      status='invitation_unknown', ok=False, created_at=time.time(),
                      automatic_retry_allowed=False, invitation_performed=None,
                      message_send_performed=False, native_voice_api_used=False)
        sending._persist(path, record)
        try:
            with desktop_session():
                native, body = dispatch(prepared, 2, operation=2)
            record.update(native=native, native_result=body)
            if not native.get('ok'):
                if native.get('state') == 2 and not native.get('native_action_entered'):
                    record.update(status='failed_no_invitation', invitation_performed=False)
                return record
            active = wait_active(prepared, None)
            record.update(status='active', ok=True, handle=active['handle'],
                          invitation_performed=True, current_state=active['state'],
                          call_connection_verified=active['call_connection_verified'])
            return record
        finally:
            sending._persist(path, record)


def answer(name, token, request_id):
    if not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('INVALID_CALL_INVITATION_TOKEN')
    intent = dict(operation='answer', account=name, invitation_token=token)
    with lock(), sending._lock():
        path = journal(request_id)
        old = replay(path, intent)
        if old:
            return old
        prepared = context(name)
        block_unresolved(prepared)
        live = observe(prepared)
        candidates = [i for i in live['incoming'] if i['invitation_token'] == token]
        if live['active'] or len(candidates) != 1:
            raise ValueError('EXACT_INCOMING_INVITATION_NOT_FOUND')
        invitation = candidates[0]['descriptor']
        record = dict(request_id=request_id, account=name, account_scope=prepared['value']['scope'],
                      process=prepared['before'][0], intent=intent, invitation=invitation,
                      status='accept_unknown', ok=False, created_at=time.time(),
                      automatic_retry_allowed=False, invitation_performed=False,
                      message_send_performed=False, caller_identity_verified=False,
                      native_voice_api_used=False)
        sending._persist(path, record)
        try:
            warm(prepared)
            payload = struct.pack('<III', int(invitation['root'], 16),
                                  int(invitation['accept_button'], 16), 0)
            with desktop_session():
                native, body = dispatch(prepared, 2, 1, invitation, payload, invitation['caption'])
            record.update(native=native, native_result=body)
            if not native.get('ok'):
                if native.get('state') == 2 and not native.get('native_action_entered'):
                    record['status'] = 'failed_no_accept'
                return record
            active = wait_active(prepared, None)
            record.update(status='active', ok=True, handle=active['handle'],
                          current_state=active['state'], accepted_invitation=True,
                          call_connection_verified=active['call_connection_verified'])
            return record
        finally:
            sending._persist(path, record)


def hangup(request_id):
    with lock(), sending._lock():
        path = journal(request_id)
        if not path.is_file():
            raise ValueError('CALL_REQUEST_NOT_FOUND')
        record = read_private(path)
        if record['status'] in ('ended', 'failed_no_invitation', 'failed_no_accept'):
            return dict(record, replayed=True, read_only=True)
        if record['status'] in UNKNOWN:
            raise ValueError('CALL_OUTCOME_UNKNOWN_QUERY_OR_RESOLVE_ORIGINAL_REQUEST')
        prepared = context(record['account'])
        record = refresh(record, prepared)
        if record['status'] == 'ended':
            sending._persist(path, record)
            return record
        active = record['live']['active']
        if not handle_matches(record, active) or not active['hangup_control_verified']:
            raise ValueError('EXACT_ORIGINAL_CALL_HANGUP_CONTROL_REQUIRED')
        bound = active['binding']
        payload = struct.pack('<III', *(int(bound[k], 16) for k in ('root', 'outer', 'inner')))
        record.update(status='hangup_unknown', hangup_observed=False, read_only=False)
        sending._persist(path, record)
        try:
            with desktop_session():
                native, body = dispatch(prepared, 2, window=active['handle'], payload=payload)
            record.update(hangup_native=native, hangup_native_result=body)
            if not native.get('ok'):
                return record
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                current = observe(prepared)
                if not handle_matches(record, current['active']):
                    record.update(status='ended', ok=True, ended_observed=True,
                                  hangup_observed=True, call_connection_verified=False,
                                  current_call_matches=False, current_state=None, live=current)
                    return record
                time.sleep(.1)
            return record
        finally:
            sending._persist(path, record)


def play(request_id, file, audio_request_id, wait_seconds=30):
    if not 0 <= wait_seconds <= 120:
        raise ValueError('CALL_CONNECTION_WAIT_MUST_BE_0_TO_120_SECONDS')
    data, _ = audio.wav_snapshot(file)
    digest = hashlib.sha256(data).hexdigest()
    with lock():
        path = journal(request_id)
        record = read_private(path)
        previous = record.get('audio_requests', {}).get(audio_request_id)
        audio_path = audio.record_path(audio_request_id)
        if previous:
            if previous['audio_sha256'] != digest:
                raise ValueError('CALL_AUDIO_REQUEST_ID_PAYLOAD_CONFLICT')
            if audio_path.exists():
                result = audio.read_record(audio_path)
                expected = dict(pid=record['process']['pid'], start_time=record['process']['start_time'],
                                stream_index=previous['stream_index'], audio_sha256=digest)
                if result['intent'] != expected:
                    raise ValueError('CALL_AUDIO_JOURNAL_CONFLICT')
                return dict(result, call_request_id=request_id, replayed=True,
                            call_connection_verified_before_playback=True,
                            playback_performed_this_invocation=False)
        elif audio_path.exists():
            raise ValueError('AUDIO_REQUEST_ALREADY_BELONGS_TO_ANOTHER_OPERATION')
        if record['status'] != 'active':
            raise ValueError('ORIGINAL_CALL_IS_NOT_ACTIVE')
        deadline = time.monotonic() + wait_seconds
        while True:
            with sending._lock():
                prepared = context(record['account'])
                current = refresh(record, prepared)
            if current.get('call_connection_verified'):
                break
            if current['status'] == 'ended' or time.monotonic() >= deadline:
                raise ValueError('CALL_CONNECTION_NOT_VERIFIED_NO_AUDIO_PLAYED')
            time.sleep(.2)
        active = current['live']['active']
        if active['kind'] != 'private':
            raise ValueError('GROUP_CONNECTION_NOT_VERIFIED_NO_AUDIO_PLAYED')
        process = record['process']
        streams = audio.streams(process['pid'], process['start_time'])['items']
        if len(streams) != 1 or streams[0]['muted'] or streams[0]['corked']:
            raise ValueError('ONE_ACTIVE_CLIENT_CAPTURE_STREAM_REQUIRED')
        stream = streams[0]['index']
        if previous and previous['stream_index'] != stream:
            raise ValueError('CALL_AUDIO_STREAM_CHANGED')
        bound = dict(audio_sha256=digest, stream_index=stream, call_handle=record['handle'])
        record.setdefault('audio_requests', {})[audio_request_id] = bound
        sending._persist(path, record)
        folder = sending._folder(private_root() / 'call-temporary')
        with tempfile.NamedTemporaryFile(dir=folder, suffix='.wav') as frozen:
            frozen.write(data)
            frozen.flush()
            result = audio.locked(audio._play, Path(frozen.name), process['pid'],
                                  process['start_time'], stream, audio_request_id)
        result = dict(result, call_request_id=request_id,
                      call_connection_verified_before_playback=True)
        record['last_audio_result'] = result
        sending._persist(path, record)
        return result


def resolve(request_id, ended):
    if not ended:
        raise ValueError('EXPLICIT_ENDED_CONFIRMATION_REQUIRED')
    with lock(), sending._lock():
        path = journal(request_id)
        record = read_private(path)
        live = observe(context(record['account']))
        if live['active'] or live['incoming']:
            raise ValueError('CLIENT_STILL_HAS_AN_ACTIVE_OR_INCOMING_CALL')
        record.update(status='ended', resolved_ended=True, call_connection_verified=False,
                      resolution_changes_local_journal_only=True)
        sending._persist(path, record)
        return record


def add_parser(sub):
    parser = sub.add_parser('call', help='Normal private voice UI; caller checks invitation/answer authorization')
    commands = parser.add_subparsers(dest='call_command', required=True)
    for command in ('inspect', 'preflight', 'start', 'answer'):
        item = commands.add_parser(command)
        item.add_argument('--account', default='me')
        if command in ('start', 'preflight'):
            item.add_argument('--chat', required=command == 'start')
        if command in ('start', 'answer'):
            item.add_argument('--request-id', required=True)
        if command == 'answer':
            item.add_argument('--invitation-token', required=True)
    for command in ('status', 'hangup', 'resolve'):
        item = commands.add_parser(command)
        item.add_argument('--request-id', required=True)
        if command == 'resolve':
            item.add_argument('--ended', action='store_true', required=True)
    item = commands.add_parser('play', help='Wait for this private call to connect, then route specified PCM WAV')
    item.add_argument('--request-id', required=True)
    item.add_argument('--audio-request-id', required=True)
    item.add_argument('--file', type=Path, required=True)
    item.add_argument('--wait-seconds', type=float, default=30)


def run(args):
    if args.call_command == 'inspect':
        return inspect(args.account)
    if args.call_command == 'preflight':
        return preflight(args.account, args.chat)
    if args.call_command == 'start':
        return start(args.account, args.chat, args.request_id)
    if args.call_command == 'answer':
        return answer(args.account, args.invitation_token, args.request_id)
    if args.call_command == 'status':
        return status(args.request_id)
    if args.call_command == 'hangup':
        return hangup(args.request_id)
    if args.call_command == 'play':
        return play(args.request_id, args.file, args.audio_request_id, args.wait_seconds)
    return resolve(args.request_id, args.ended)
