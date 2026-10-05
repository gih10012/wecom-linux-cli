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
UNKNOWN = {'prepared', 'invitation_unknown', 'accept_unknown', 'hangup_unknown', 'group_prepare_unknown',
           'group_submission_unknown'}


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
    files = ('call_hook.c', 'call_probe.c', 'message_hook.h', 'selection_snapshot.h')
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


def selector_members(window_type, nodes):
    """Expose only version-verified individual checkbox metadata formats.

    Creation pickers also contain departments: their metadata is not a user ID.
    Only the external individual format has been verified for Frame2 so far.
    """
    members = []
    for node in nodes:
        if node.get('control_type') != 'WCheckbox' or type(node.get('self_selected')) is not bool:
            continue
        raw = node.get('user_data')
        if not isinstance(raw, str):
            continue
        pattern = r'([1-9][0-9]{0,19})' if window_type == 'CSelectUserFrame' else r'([1-9][0-9]{0,19}),0,;0,1,0'
        match = re.fullmatch(pattern, raw)
        pointer = node.get('pointer')
        if (not match or int(match[1]) >= 2**64 or not isinstance(pointer, str) or
                not re.fullmatch(r'[0-9a-fA-F]{1,8}', pointer) or not int(pointer, 16)):
            continue
        members.append(dict(native_id=match[1], selected=node['self_selected'],
                            checkbox=pointer, user_data=raw))
    ids = [m['native_id'] for m in members]
    if len(ids) != len(set(ids)):
        raise ValueError('AMBIGUOUS_MEMBER_CHECKBOX_IDENTITY')
    return members


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
    if window['kind'] == 'member_selector':
        window_type = window.get('selector_type', 'CSelectUserFrame')
        expected_title = {'CSelectUserFrame': '选择联系人', 'CSelectUserFrame2': '发起群聊'}.get(window_type)
        if (not expected_title or label('selectedtitle') != expected_title or
                any(sum(n.get('name') == name for n in nodes) != 1
                    for name in ('okbtn', 'cancelbtn', 'searchedit'))):
            raise ValueError('COMPLETE_MEMBER_SELECTOR_SNAPSHOT_REQUIRED')
        # The same normal window type serves several selection workflows.
        # Captions and checkboxes do not bind native member IDs or prove that
        # a voice invitation was submitted. Never classify this as a call.
        members = selector_members(window_type, nodes)
        group = tree.get('bound_group_chat')
        group_verified = (window_type == 'CSelectUserFrame' and tree.get('group_binding_verified') is True
                          and isinstance(group, str) and re.fullmatch(r'R:[0-9]{1,20}', group) is not None)
        result = dict(kind='member_selector', selector_type=window_type, handle=handle,
                    bound_group_chat=group if group_verified else None,
                    group_binding_verified=group_verified,
                    selector_caption=label('selectedtitle'),
                    conversation_caption=label('conversation_name'),
                    search_text=label('searchedit'),
                    visible_checkbox_count=sum(n.get('control_type') == 'WCheckbox' or
                                               n.get('name') == 'checkbox' for n in nodes),
                    visible_members=members, visible_member_states_verified=bool(members),
                    selected_visible_member_ids=[m['native_id'] for m in members if m['selected']],
                    full_member_list_verified=False,
                    node_count=tree.get('node_count'), read_only=True,
                    selector_purpose_verified=False, member_identity_verified=bool(members),
                    selection_verified=False, call_connection_verified=False)
        model = tree.get('selected_member_model')
        if window_type == 'CSelectUserFrame' and isinstance(model, dict) and model.get('verified') is True:
            ids = model.get('ids')
            counts = [model.get(k) for k in ('count', 'object_count', 'additional_count')]
            if (model.get('source') != 'classic_live_buddy_selection' or not isinstance(ids, list) or
                    any(type(c) is not int or not 0 <= c <= 256 for c in counts) or counts[0] != len(ids) or
                    not counts[1] <= counts[0] <= counts[1] + counts[2] or
                    any(not isinstance(uid, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', uid) or
                        int(uid) >= 2**64 for uid in ids) or len(set(ids)) != len(ids)):
                raise ValueError('INVALID_NATIVE_SELECTED_MEMBER_MODEL')
            selected = set(ids)
            if any(m['selected'] != (m['native_id'] in selected) for m in members):
                raise ValueError('NATIVE_SELECTION_DISAGREES_WITH_VISIBLE_CHECKBOX')
            result.update(native_selected_member_ids=ids, native_selected_member_count=len(ids),
                          native_selected_member_model_verified=True)
        else:
            result.update(native_selected_member_ids=None, native_selected_member_count=None,
                          native_selected_member_model_verified=False)
        callback = tree.get('group_call_callback')
        callback_verified = group_verified and isinstance(callback, dict) and callback.get('verified') is True
        if callback_verified:
            if (any(not isinstance(callback.get(k), str) or not re.fullmatch(r'[0-9a-fA-F]{1,8}', callback[k])
                    or not int(callback[k], 16) for k in ('object', 'chat_view')) or
                    type(callback.get('response_limit')) is not int or not 0 <= callback['response_limit'] < 2**32 or
                    type(callback.get('response_flag')) is not bool):
                raise ValueError('INVALID_NATIVE_GROUP_CALL_CALLBACK')
            callback = {k: callback[k] for k in ('object', 'chat_view', 'response_limit', 'response_flag')}
        else:
            callback = None
        result.update(native_group_call_callback_verified=bool(callback_verified), group_call_callback=callback)
        selection_context = tree.get('selection_context')
        confirmation_verified = (window_type == 'CSelectUserFrame' and
                                 result['native_selected_member_model_verified'] and
                                 isinstance(selection_context, dict) and
                                 selection_context.get('verified') is True)
        if confirmation_verified:
            if (any(not isinstance(selection_context.get(k), str) or
                    not re.fullmatch(r'[0-9a-fA-F]{1,8}', selection_context[k]) or
                    not int(selection_context[k], 16)
                    for k in ('common_view', 'buddy_list', 'ok_button')) or
                    type(selection_context.get('ok_enabled')) is not bool):
                raise ValueError('INVALID_NATIVE_SELECTION_CONTEXT')
            result['confirmation_descriptor'] = dict(
                handle, **{k: selection_context[k] for k in ('common_view', 'buddy_list', 'ok_button')},
                ok_enabled=selection_context['ok_enabled'])
        result['native_confirmation_control_verified'] = bool(confirmation_verified)
        cancel = tree.get('cancel_button')
        if (tree.get('cancel_count') == tree.get('cancel_caption_count') == 1 and
                isinstance(cancel, str) and re.fullmatch(r'[0-9a-fA-F]+', cancel) and int(cancel, 16)):
            descriptor = dict(handle, cancel_button=cancel, caption=label('selectedtitle'),
                              selector_type=window_type,
                              bound_group_chat=result['bound_group_chat'],
                              conversation_caption=result['conversation_caption'],
                              account_scope=prepared['value']['scope'])
            result.update(cancel_descriptor=descriptor, selector_token=hashlib.sha256(
                json.dumps(descriptor, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
                cancel_control_verified=True)
        else:
            result['cancel_control_verified'] = False
        return result
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
    incoming, active, ended, selectors = [], [], [], []
    for window in probe(prepared):
        if 'hwnd' not in window or window['tid'] != prepared['resolution']['tid']:
            continue
        native, tree = dispatch(prepared, 1, window=window)
        if not native.get('ok'):
            raise ValueError('CALL_WINDOW_READ_FAILED_' + str(native.get('failure')))
        item = classify(prepared, window, tree)
        if not item:
            continue
        if item['kind'] == 'member_selector':
            selectors.append(item)
        elif item['kind'] == 'incoming':
            incoming.append(item)
        elif item['state'] == 'ended':
            ended.append(item)
        else:
            active.append(item)
    if len(active) > 1:
        raise ValueError('MULTIPLE_ACTIVE_CALL_WINDOWS')
    return dict(ok=True, read_only=True, transport='normal_duilib_ui_thread',
                incoming=incoming, active=active[0] if active else None, ended=ended,
                member_selectors=selectors,
                call_connection_verified=bool(active and active[0]['call_connection_verified']))


def inspect(name='me'):
    with sending._lock():
        return observe(context(name))


def selector_cancel(name, token):
    """Cancel one current local picker; this never submits a voice invitation."""
    if not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('INVALID_MEMBER_SELECTOR_TOKEN')
    with lock(), sending._lock():
        prepared = context(name)
        live = observe(prepared)
        candidates = [s for s in live.get('member_selectors', [])
                      if s.get('selector_token') == token and s.get('cancel_control_verified')]
        if len(candidates) != 1:
            raise ValueError('EXACT_MEMBER_SELECTOR_CANCEL_CONTROL_NOT_FOUND')
        descriptor = candidates[0]['cancel_descriptor']
        payload = struct.pack('<III', int(descriptor['root'], 16),
                              int(descriptor['cancel_button'], 16), 0)
        with desktop_session():
            native, body = dispatch(prepared, 2, 3, descriptor, payload)
        after = observe(prepared)
        closed = not any(s['handle'] == candidates[0]['handle']
                         for s in after.get('member_selectors', []))
        return dict(ok=bool(native.get('ok') and body and body.get('activated') and closed),
                    selector_closed_observed=closed,
                    native=native, native_result=body, live=after,
                    invitation_performed=False, message_send_performed=False,
                    automatic_retry_allowed=False)


def selector_select(name, token, member_id, selected):
    """Set one current visible member checkbox; never activate OK or invite."""
    if not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('INVALID_MEMBER_SELECTOR_TOKEN')
    if (not re.fullmatch(r'[1-9][0-9]{0,19}', member_id) or int(member_id) >= 2**64 or
            type(selected) is not bool):
        raise ValueError('INVALID_MEMBER_SELECTION')
    with lock(), sending._lock():
        prepared = context(name)
        live = observe(prepared)
        selectors = [s for s in live.get('member_selectors', [])
                     if s.get('selector_token') == token and s.get('cancel_control_verified')]
        if len(selectors) != 1:
            raise ValueError('EXACT_MEMBER_SELECTOR_NOT_FOUND')
        selector = selectors[0]
        members = [m for m in selector['visible_members'] if m['native_id'] == member_id]
        if len(members) != 1:
            raise ValueError('ONE_VISIBLE_NATIVE_MEMBER_CHECKBOX_REQUIRED')
        member = members[0]
        if member['selected'] == selected:
            return dict(ok=True, read_only=True, already_selected_state=True,
                        member_id=member_id, selected=selected, live=live,
                        invitation_performed=False, automatic_retry_allowed=False)
        descriptor = selector['cancel_descriptor']
        payload = struct.pack('<IIII', int(descriptor['root'], 16),
                              int(member['checkbox'], 16), int(member['selected']), int(selected))
        payload += member['user_data'].encode('utf-16-le') + b'\0\0'
        with desktop_session():
            native, body = dispatch(prepared, 2, 5, descriptor, payload)
        after = observe(prepared)
        current = [s for s in after.get('member_selectors', []) if s['handle'] == selector['handle']]
        observed = [m for s in current for m in s['visible_members'] if m['native_id'] == member_id]
        verified = len(observed) == 1 and observed[0]['selected'] == selected
        return dict(ok=bool(native.get('ok') and body and body.get('activated') and verified),
                    member_id=member_id, selected=selected, selection_change_observed=verified,
                    native=native, native_result=body, live=after,
                    invitation_performed=False, message_send_performed=False,
                    automatic_retry_allowed=False)


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
            require_no_selector(result)
            prepared = prepare_start(prepared)
            native, body = dispatch(prepared, 1, operation=2)
            result.update(ok=bool(native.get('ok')), target_preflight=body, native=native)
        return result


def prepare_start(prepared):
    if not re.fullmatch(r'S:\d+_\d+', prepared['chat']):
        raise ValueError('PRIVATE_CALL_CHAT_REQUIRED_GROUP_INVITATIONS_NOT_IMPLEMENTED')
    return prepare_view(prepared)


def prepare_view(prepared):
    rows = probe(prepared, prepared['chat'])
    views = [r for r in rows if r.get('exact_requested_chat_matches')]
    if len(views) != 1 or not rows[-1].get('scan_complete'):
        raise ValueError('ONE_CACHED_ATTACHED_CHAT_VIEW_REQUIRED_OPEN_TARGET_IN_CLIENT')
    return dict(prepared, width=int(views[0]['view'], 16),
                height=int(prepared['resolution']['hwnd'], 16))


def handle_matches(record, live):
    return live is not None and record.get('handle') == live.get('handle')


def require_no_selector(live):
    if live.get('member_selectors'):
        raise ValueError('MEMBER_SELECTOR_OPEN_CLOSE_OR_CANCEL_BEFORE_CALL')


def bind_voice_origin(record, selector):
    """A shared group-call predicate alone cannot distinguish voice/video.

    Only the journaled normal voice opening and its captured exact chat view
    can establish this picker's origin. Old records lacking that evidence do
    not gain a voice-purpose claim from an unrelated current window.
    """
    intent = record.get('intent', {})
    callback = selector.get('group_call_callback')
    verified = (record.get('status') == 'member_selector_open' and
                record.get('normal_voice_entry_verified') is True and
                intent.get('operation') == 'group_prepare' and
                intent.get('account') == record.get('account') and
                intent.get('chat') == record.get('chat_id') and
                record.get('chat_id') == selector.get('bound_group_chat') and
                selector.get('group_binding_verified') is True and
                handle_matches(record, selector) and
                selector.get('native_group_call_callback_verified') is True and
                isinstance(record.get('group_call_callback'), dict) and
                isinstance(callback, dict) and
                record['group_call_callback'] == callback and
                record.get('chat_view') == callback.get('chat_view'))
    return dict(selector, selector_purpose_verified=verified,
                voice_origin_request_id=record['request_id'] if verified else None)


def refresh(record, prepared):
    if prepared['value']['scope'] != record['account_scope']:
        raise ValueError('CALL_ACCOUNT_CHANGED')
    if prepared['before'][0] != record['process']:
        if process_alive(record):
            raise ValueError('ORIGINAL_CALL_CLIENT_STILL_RUNNING')
        return dict(record, status='ended', client_process_ended=True,
                    **({'voice_origin_verified': False} if 'voice_origin_verified' in record else {}),
                    call_connection_verified=False, read_only=True)
    live = observe(prepared)
    if record.get('intent', {}).get('operation') == 'group_invite':
        # A normal button return or picker closure is not an independently
        # observed invitation, nor an exact group-call binding.
        still_open = any(handle_matches(dict(handle=record['selector_handle']), s)
                         for s in live.get('member_selectors', []))
        return dict(record, live=live, read_only=True, original_selector_open=still_open,
                    call_connection_verified=False)
    if record.get('intent', {}).get('operation') == 'group_prepare':
        selectors = [s for s in live.get('member_selectors', []) if handle_matches(record, s)]
        if any(not s.get('group_binding_verified') or s.get('bound_group_chat') != record['chat_id']
               for s in selectors):
            raise ValueError('ORIGINAL_GROUP_SELECTOR_BINDING_CHANGED')
        result = dict(record, live=live, read_only=True, call_connection_verified=False,
                      current_selector_matches=len(selectors) == 1)
        if len(selectors) == 1:
            selector = bind_voice_origin(record, selectors[0])
            if record.get('voice_origin_verified') and not selector['selector_purpose_verified']:
                raise ValueError('ORIGINAL_GROUP_VOICE_ORIGIN_CHANGED')
            result.update(selector=selector, voice_origin_verified=selector['selector_purpose_verified'])
        elif record.get('handle'):
            result.update(status='ended', selector_closed_observed=True, voice_origin_verified=False)
        return result
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
            if 'voice_origin_verified' in record:
                record['voice_origin_verified'] = False
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
        if record.get('status') == 'member_selector_open':
            record = refresh(record, prepared)
            sending._persist(path, record)
            if record['status'] != 'ended':
                raise ValueError('MEMBER_SELECTOR_ALREADY_OPEN')


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


def group_prepare(name, chat, request_id):
    """Open the exact group's empty normal picker; never select or submit."""
    if not re.fullmatch(r'R:[0-9]{1,20}', chat):
        raise ValueError('EXACT_GROUP_CHAT_ID_REQUIRED')
    intent = dict(operation='group_prepare', account=name, chat=chat)
    with lock(), sending._lock():
        path = journal(request_id)
        old = replay(path, intent)
        if old:
            return old
        prepared = context(name, chat)
        before = observe(prepared)
        require_no_selector(before)
        block_unresolved(prepared)
        if before['active'] or before['incoming']:
            raise ValueError('CALL_ALREADY_ACTIVE_OR_INCOMING')
        prepared = prepare_view(prepared)
        warm(prepared)
        checked, _ = dispatch(prepared, 1, operation=6)
        if not checked.get('ok'):
            return dict(ok=False, code='GROUP_PICKER_TARGET_PREFLIGHT_FAILED', native=checked,
                        invitation_performed=False, automatic_retry_allowed=False)
        record = dict(request_id=request_id, account=name, account_scope=prepared['value']['scope'],
                      chat_id=prepared['chat'], process=prepared['before'][0], intent=intent,
                      chat_view=format(prepared['width'], 'x'),
                      status='group_prepare_unknown', ok=False, created_at=time.time(),
                      automatic_retry_allowed=False, invitation_performed=False,
                      message_send_performed=False, call_connection_verified=False)
        sending._persist(path, record)
        try:
            with desktop_session():
                native, body = dispatch(prepared, 2, operation=6)
            record.update(native=native, native_result=body)
            if not native.get('ok'):
                if native.get('state') == 2 and not native.get('native_action_entered'):
                    record['status'] = 'failed_no_invitation'
                return record
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                live = observe(prepared)
                selectors = live.get('member_selectors', [])
                if selectors:
                    if (len(selectors) != 1 or not selectors[0].get('group_binding_verified') or
                            selectors[0]['bound_group_chat'] != prepared['chat'] or
                            live['active'] or live['incoming']):
                        raise ValueError('EXACT_GROUP_PICKER_NOT_VERIFIED_RESULT_UNKNOWN')
                    selector = selectors[0]
                    if (not selector.get('native_group_call_callback_verified') or
                            selector['group_call_callback']['chat_view'] != record['chat_view']):
                        raise ValueError('EXACT_GROUP_CALL_CALLBACK_NOT_VERIFIED_RESULT_UNKNOWN')
                    record.update(status='member_selector_open', ok=True, handle=selector['handle'],
                                  selector=selector, group_binding_verified=True,
                                  normal_voice_entry_verified=True, group_call_callback=selector['group_call_callback'])
                    record['selector'] = bind_voice_origin(record, selector)
                    record['voice_origin_verified'] = record['selector']['selector_purpose_verified']
                    return record
                if live['active'] or live['incoming']:
                    raise ValueError('UNEXPECTED_CALL_DURING_GROUP_PREPARATION')
                time.sleep(.1)
            raise ValueError('GROUP_PICKER_NOT_OBSERVED_RESULT_UNKNOWN')
        finally:
            sending._persist(path, record)


def group_invite(prepare_request_id, member_ids, request_id):
    """Confirm an exact original voice picker once, with its entire selected set.

    Submission remains unknown until an independent invitation outcome is
    available. A successful normal button activation does not prove delivery.
    """
    if (not isinstance(member_ids, list) or not 1 <= len(member_ids) <= 256 or
            any(not isinstance(uid, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', uid) or
                int(uid) >= 2**64 for uid in member_ids) or len(set(member_ids)) != len(member_ids)):
        raise ValueError('EXACT_NONEMPTY_UNIQUE_GROUP_MEMBER_IDS_REQUIRED')
    members = sorted(member_ids, key=int)
    with lock(), sending._lock():
        parent_path = journal(prepare_request_id)
        origin = read_private(parent_path)
        intent = dict(operation='group_invite', account=origin['account'], chat=origin['chat_id'],
                      prepare_request_id=prepare_request_id, member_ids=members)
        path = journal(request_id)
        old = replay(path, intent)
        if old:
            return old
        if origin.get('submission_request_id'):
            raise ValueError('GROUP_PREPARATION_ALREADY_SUBMITTED_QUERY_ORIGINAL_REQUEST')
        prepared = context(origin['account'], origin['chat_id'])
        current = refresh(origin, prepared)
        selector = current.get('selector')
        if (current.get('status') != 'member_selector_open' or not current.get('current_selector_matches') or
                current.get('voice_origin_verified') is not True or not isinstance(selector, dict) or
                selector.get('selector_purpose_verified') is not True):
            raise ValueError('EXACT_ORIGINAL_NORMAL_VOICE_PICKER_REQUIRED')
        live = current['live']
        if live['active'] or live['incoming'] or len(live.get('member_selectors', [])) != 1:
            raise ValueError('ONE_IDLE_ORIGINAL_GROUP_PICKER_REQUIRED')
        if (selector.get('native_selected_member_model_verified') is not True or
                set(selector['native_selected_member_ids']) != set(members) or
                prepared['value']['self_id'] in members):
            raise ValueError('ENTIRE_NATIVE_SELECTED_SET_MUST_MATCH_EXPECTED_MEMBERS')
        if (selector.get('native_confirmation_control_verified') is not True or
                not selector['confirmation_descriptor']['ok_enabled']):
            raise ValueError('EXACT_ENABLED_NORMAL_GROUP_CONFIRM_CONTROL_REQUIRED')
        for other in path.parent.glob('*.json'):
            if other == parent_path:
                continue
            record = read_private(other)
            if record.get('account_scope') == current['account_scope'] and record.get('status') in UNKNOWN:
                raise ValueError('CALL_OUTCOME_UNKNOWN_QUERY_OR_RESOLVE_ORIGINAL_REQUEST')
        descriptor, callback = selector['confirmation_descriptor'], selector['group_call_callback']
        payload = struct.pack('<IIIIIIIII', *(int(descriptor[k], 16)
                              for k in ('root', 'ok_button', 'common_view', 'buddy_list')),
                              int(callback['object'], 16), int(callback['chat_view'], 16),
                              callback['response_limit'], int(callback['response_flag']), len(members))
        payload += b''.join(struct.pack('<Q', int(uid)) for uid in members)
        checked, body = dispatch(prepared, 1, 7, descriptor, payload)
        if not checked.get('ok') or not body or body.get('group_submit_guard_verified') is not True:
            return dict(ok=False, code='GROUP_SUBMISSION_PREFLIGHT_FAILED', native=checked,
                        native_result=body, invitation_performed=False, automatic_retry_allowed=False)
        record = dict(request_id=request_id, account=origin['account'], account_scope=current['account_scope'],
                      chat_id=origin['chat_id'], process=current['process'], intent=intent,
                      selector_handle=selector['handle'], status='group_submission_unknown',
                      expected_member_ids=members, ok=False, created_at=time.time(),
                      voice_origin_verified_before_submission=True, full_selected_set_verified_before_submission=True,
                      invitation_performed=None, call_connection_verified=False, automatic_retry_allowed=False)
        sending._persist(path, record)
        # Link the preparation before entering native code too. A different
        # request ID cannot re-confirm this same picker after a timeout.
        current['submission_request_id'] = request_id
        sending._persist(parent_path, current)
        try:
            with desktop_session():
                native, body = dispatch(prepared, 2, 7, descriptor, payload)
            record.update(native=native, native_result=body)
            if native.get('state') == 2 and not native.get('native_action_entered'):
                record.update(status='failed_no_invitation', invitation_performed=False)
            record.update(live=observe(prepared))
            record['original_selector_open'] = any(s['handle'] == selector['handle']
                                                   for s in record['live'].get('member_selectors', []))
            return record
        finally:
            sending._persist(path, record)


def start(name, chat, request_id):
    intent = dict(operation='start', account=name, chat=chat)
    with lock(), sending._lock():
        path = journal(request_id)
        old = replay(path, intent)
        if old:
            return old
        prepared = context(name, chat)
        before = observe(prepared)
        require_no_selector(before)
        prepared = prepare_start(prepared)
        block_unresolved(prepared)
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
        require_no_selector(live)
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
        if record.get('intent', {}).get('operation') == 'group_prepare':
            raise ValueError('LOCAL_GROUP_PICKER_USE_SELECTOR_CANCEL')
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
        if live['active'] or live['incoming'] or live.get('member_selectors'):
            raise ValueError('CLIENT_STILL_HAS_AN_ACTIVE_OR_INCOMING_CALL')
        record.update(status='ended', resolved_ended=True, call_connection_verified=False,
                      resolution_changes_local_journal_only=True)
        sending._persist(path, record)
        return record


def add_parser(sub):
    parser = sub.add_parser('call', help='Normal private voice UI; caller checks invitation/answer authorization')
    commands = parser.add_subparsers(dest='call_command', required=True)
    for command in ('inspect', 'preflight', 'start', 'answer', 'group-prepare', 'selector-cancel', 'selector-select'):
        item = commands.add_parser(command)
        item.add_argument('--account', default='me')
        if command in ('start', 'preflight', 'group-prepare'):
            item.add_argument('--chat', required=command != 'preflight')
        if command in ('start', 'answer', 'group-prepare'):
            item.add_argument('--request-id', required=True)
        if command == 'answer':
            item.add_argument('--invitation-token', required=True)
        if command in ('selector-cancel', 'selector-select'):
            item.add_argument('--selector-token', required=True)
        if command == 'selector-select':
            item.add_argument('--member-id', required=True)
            state = item.add_mutually_exclusive_group(required=True)
            state.add_argument('--select', action='store_true', dest='selected')
            state.add_argument('--deselect', action='store_false', dest='selected')
    for command in ('status', 'hangup', 'resolve'):
        item = commands.add_parser(command)
        item.add_argument('--request-id', required=True)
        if command == 'resolve':
            item.add_argument('--ended', action='store_true', required=True)
    item = commands.add_parser('group-invite', help='Confirm the entire selected set once; real group acceptance pending')
    item.add_argument('--prepare-request-id', required=True)
    item.add_argument('--request-id', required=True)
    item.add_argument('--member-id', action='append', required=True, dest='member_ids')
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
    if args.call_command == 'group-prepare':
        return group_prepare(args.account, args.chat, args.request_id)
    if args.call_command == 'group-invite':
        return group_invite(args.prepare_request_id, args.member_ids, args.request_id)
    if args.call_command == 'answer':
        return answer(args.account, args.invitation_token, args.request_id)
    if args.call_command == 'selector-cancel':
        return selector_cancel(args.account, args.selector_token)
    if args.call_command == 'selector-select':
        return selector_select(args.account, args.selector_token, args.member_id, args.selected)
    if args.call_command == 'status':
        return status(args.request_id)
    if args.call_command == 'hangup':
        return hangup(args.request_id)
    if args.call_command == 'play':
        return play(args.request_id, args.file, args.audio_request_id, args.wait_seconds)
    return resolve(args.request_id, args.ended)
