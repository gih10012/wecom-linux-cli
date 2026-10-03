from contextlib import nullcontext
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

import test_messages
from wecom_linux_cli import call
from wecom_linux_cli.messages import account


class CallTests(unittest.TestCase):
    setUp = test_messages.MessageReadTests.setUp
    tearDown = test_messages.MessageReadTests.tearDown

    def prepared(self, name='me', chat=None):
        return dict(value=account(name), chat=chat or 'S:123_123',
                    before=[dict(pid=123, start_time=456)],
                    probe=dict(windows_pid=8, creation_filetime=9))

    def active(self, hwnd='10'):
        return dict(kind='private', handle=dict(windows_pid=8, creation_filetime=9,
                                               hwnd=hwnd, root='20'), state='connected',
                    call_connection_verified=True, hangup_control_verified=True,
                    binding=dict(root='20', outer='30', inner='40'))

    def idle(self, active=None):
        return dict(ok=True, incoming=[], active=active, call_connection_verified=bool(active))

    def record(self, status='active'):
        return dict(account='me', account_scope=account('me')['scope'],
                    process=dict(pid=123, start_time=456), handle=self.active()['handle'],
                    request_id='call-test-01', status=status, ok=True,
                    invitation_performed=True, automatic_retry_allowed=False)

    def save(self, record):
        call.sending._persist(call.journal('call-test-01'), record)

    def test_connected_requires_private_elapsed_clock_and_hangup_control(self):
        window = dict(kind='voice', hwnd='10', root='20')
        tree = dict(complete=True, window_root='20', outer_count=1, inner_count=1,
                    nodes=[dict(name='middle_tips', text='已接通'),
                           dict(name='titletext', text='00:01'),
                           dict(name='avatar_name', text='peer')])
        self.assertTrue(call.classify(self.prepared(), window, tree)['call_connection_verified'])
        for name, text in [('middle_tips', '正在呼叫'), ('middle_tips', '已挂断'),
                           ('titletext', 'waiting'), ('titletext', '00:99')]:
            changed = dict(tree, nodes=[dict(n, text=text) if n['name'] == name else n
                                        for n in tree['nodes']])
            self.assertFalse(call.classify(self.prepared(), window, changed)['call_connection_verified'])
        group = dict(tree, nodes=tree['nodes'][:-1])
        self.assertEqual(call.classify(self.prepared(), window, group)['kind'], 'group_unverified')
        self.assertFalse(call.classify(self.prepared(), window, group)['call_connection_verified'])
        no_button = dict(tree, inner_count=0)
        self.assertFalse(call.classify(self.prepared(), window, no_button)['call_connection_verified'])

    def test_faded_connected_tip_does_not_hide_live_private_call_clock(self):
        window = dict(kind='voice', hwnd='10', root='20')
        tree = dict(complete=True, window_root='20', outer_count=1, inner_count=1,
                    nodes=[dict(name='titletext', text='00:08'),
                           dict(name='avatar_name', text='peer')])
        result = call.classify(self.prepared(), window, tree)
        self.assertTrue(result['call_connection_verified'])
        self.assertEqual(result['state'], 'connected')
        ambiguous = dict(tree, nodes=tree['nodes'] + [
            dict(name='middle_tips', text='已接通'), dict(name='middle_tips', text='正在呼叫')])
        self.assertFalse(call.classify(self.prepared(), window, ambiguous)['call_connection_verified'])

    def test_partial_tree_or_recycled_root_is_rejected(self):
        for tree in [dict(complete=False, window_root='20'), dict(complete=True, window_root='21')]:
            with self.assertRaisesRegex(ValueError, 'COMPLETE_CALL_WINDOW'):
                call.classify(self.prepared(), dict(kind='voice', root='20'), tree)

    def test_invitation_token_binds_caption_window_button_and_account(self):
        window = dict(kind='possible_invitation', hwnd='10', root='20')
        tree = dict(complete=True, window_root='20', accept_count=1, accept_button='30',
                    nodes=[dict(name='single_voip_tips', text='邀请你语音通话'),
                           dict(name='inviter_name', text='peer'), dict(name='reject_btn', text='')])
        first = call.classify(self.prepared(), window, tree)
        second = call.classify(self.prepared(), window, dict(tree, accept_button='31'))
        third = call.classify(self.prepared(), dict(window, hwnd='11'), tree)
        fourth = call.classify(self.prepared(), window, dict(tree, nodes=[
            dict(n, text='other') if n['name'] == 'inviter_name' else n for n in tree['nodes']]))
        self.assertEqual(len({x['invitation_token'] for x in [first, second, third, fourth]}), 4)
        self.assertFalse(first['caller_identity_verified'])

    def fake_start_dispatch(self, prepared, mode, operation=0, **kwargs):
        if mode == 2:
            record = json.loads(call.journal('call-test-01').read_text())
            self.assertEqual(record['status'], 'invitation_unknown')
            self.assertFalse(record['automatic_retry_allowed'])
        return dict(ok=True, state=2, native_action_entered=mode == 2), {}

    def start_patches(self, dispatch):
        return (patch.object(call, 'context', side_effect=self.prepared),
                patch.object(call, 'prepare_start', side_effect=lambda p: p),
                patch.object(call, 'observe', return_value=self.idle()),
                patch.object(call, 'warm'),
                patch.object(call, 'desktop_session', side_effect=nullcontext),
                patch.object(call, 'wait_active', return_value=self.active()),
                patch.object(call, 'dispatch', side_effect=dispatch))

    def test_start_replay_and_changed_payload_never_invite_again(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            mocks = [stack.enter_context(p) for p in self.start_patches(self.fake_start_dispatch)]
            self.assertTrue(call.start('me', 'S:123_456', 'call-test-01')['invitation_performed'])
            self.assertTrue(call.start('me', 'S:123_456', 'call-test-01')['replayed'])
            with self.assertRaisesRegex(ValueError, 'PAYLOAD_CONFLICT'):
                call.start('me', 'S:123_789', 'call-test-01')
            self.assertEqual(sum(c.args[1] == 2 for c in mocks[-1].call_args_list), 1)

    def test_timeout_preserves_unknown_and_blocks_new_id(self):
        from contextlib import ExitStack
        def dispatch(p, mode, operation=0):
            if mode == 2:
                raise subprocess.TimeoutExpired('hook', 30)
            return dict(ok=True), {}
        with ExitStack() as stack:
            mocks = [stack.enter_context(p) for p in self.start_patches(dispatch)]
            with self.assertRaises(subprocess.TimeoutExpired):
                call.start('me', 'S:123_456', 'call-test-01')
            old = call.start('me', 'S:123_456', 'call-test-01')
            self.assertEqual(old['status'], 'invitation_unknown')
            with self.assertRaisesRegex(ValueError, 'OUTCOME_UNKNOWN'):
                call.start('me', 'S:123_456', 'call-test-02')
            self.assertEqual(sum(c.args[1] == 2 for c in mocks[-1].call_args_list), 1)

    def test_crash_after_entry_preserves_durable_unknown(self):
        from contextlib import ExitStack
        def dispatch(p, mode, operation=0):
            if mode == 2:
                raise KeyboardInterrupt()
            return dict(ok=True), {}
        with ExitStack() as stack:
            for p in self.start_patches(dispatch):
                stack.enter_context(p)
            with self.assertRaises(KeyboardInterrupt):
                call.start('me', 'S:123_456', 'call-test-01')
            self.assertEqual(call.start('me', 'S:123_456', 'call-test-01')['status'], 'invitation_unknown')

    def test_failed_preflight_never_invites(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            mocks = [stack.enter_context(p) for p in self.start_patches(lambda *a, **k: ({'ok': False}, {}))]
            self.assertFalse(call.start('me', 'S:123_456', 'call-test-01')['invitation_performed'])
            self.assertEqual(mocks[-1].call_count, 1)

    def test_hangup_cannot_control_a_different_current_call(self):
        self.save(self.record())
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=self.idle(self.active('11'))), \
             patch.object(call, 'dispatch') as dispatch:
            self.assertEqual(call.hangup('call-test-01')['status'], 'ended')
            dispatch.assert_not_called()

    def test_uncertain_hangup_cannot_be_submitted_again(self):
        self.save(self.record())
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=self.idle(self.active())), \
             patch.object(call, 'desktop_session', side_effect=nullcontext), \
             patch.object(call, 'dispatch', side_effect=subprocess.TimeoutExpired('hook', 30)) as dispatch:
            with self.assertRaises(subprocess.TimeoutExpired):
                call.hangup('call-test-01')
            self.assertEqual(json.loads(call.journal('call-test-01').read_text())['status'], 'hangup_unknown')
            with self.assertRaisesRegex(ValueError, 'OUTCOME_UNKNOWN'):
                call.hangup('call-test-01')
            self.assertEqual(dispatch.call_count, 1)

    def test_completed_hangup_clears_old_live_connection_and_is_readonly_on_replay(self):
        self.save(self.record())
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', side_effect=[self.idle(self.active()), self.idle()]), \
             patch.object(call, 'desktop_session', side_effect=nullcontext), \
             patch.object(call, 'dispatch', return_value=({'ok': True}, {})) as dispatch:
            result = call.hangup('call-test-01')
            self.assertEqual(result['status'], 'ended')
            self.assertFalse(result['read_only'])
            self.assertFalse(result['current_call_matches'])
            self.assertFalse(result['call_connection_verified'])
            self.assertIsNone(result['live']['active'])
            self.assertTrue(call.hangup('call-test-01')['read_only'])
            self.assertEqual(dispatch.call_count, 1)

    def test_ended_call_audio_replay_is_bound_to_original_journal_without_playing(self):
        data = b'valid wav';digest = hashlib.sha256(data).hexdigest()
        record = self.record('ended')
        record['audio_requests'] = {'audio-test-01': dict(audio_sha256=digest, stream_index=7)}
        self.save(record)
        audio_path = call.audio.record_path('audio-test-01')
        old = dict(ok=True, status='playback_finished', intent=dict(
            pid=123, start_time=456, stream_index=7, audio_sha256=digest))
        call.audio.write_record(audio_path, old)
        with patch.object(call.audio, 'wav_snapshot', return_value=(data, 1)), \
             patch.object(call, 'context') as context, patch.object(call.audio, '_play') as play:
            result = call.play('call-test-01', 'file.wav', 'audio-test-01')
            self.assertTrue(result['replayed'])
            self.assertTrue(result['call_connection_verified_before_playback'])
            self.assertFalse(result['playback_performed_this_invocation'])
            context.assert_not_called();play.assert_not_called()
            call.audio.write_record(audio_path, dict(old, intent=dict(old['intent'], pid=999)))
            with self.assertRaisesRegex(ValueError, 'JOURNAL_CONFLICT'):
                call.play('call-test-01', 'file.wav', 'audio-test-01')

    def test_silent_ringing_cannot_play_despite_existing_capture_stream(self):
        self.save(self.record())
        ringing = dict(self.active(), state='calling', call_connection_verified=False)
        with patch.object(call.audio, 'wav_snapshot', return_value=(b'valid wav', 1)), \
             patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=dict(self.idle(ringing), call_connection_verified=False)), \
             patch.object(call.audio, 'streams') as streams, patch.object(call.audio, '_play') as play:
            with self.assertRaisesRegex(ValueError, 'CONNECTION_NOT_VERIFIED'):
                call.play('call-test-01', 'file.wav', 'audio-test-01', 0)
            streams.assert_not_called()
            play.assert_not_called()

    def test_changed_incoming_token_cannot_be_accepted(self):
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=dict(self.idle(), incoming=[
                 dict(invitation_token='b' * 64)])), patch.object(call, 'dispatch') as dispatch:
            with self.assertRaisesRegex(ValueError, 'EXACT_INCOMING'):
                call.answer('me', 'a' * 64, 'call-test-01')
            dispatch.assert_not_called()

    def test_exit_preserves_unknown_invitation_outcome_without_new_native_work(self):
        record = self.record('invitation_unknown')
        record.pop('handle')
        record['invitation_performed'] = None
        self.save(record)
        with patch.object(call, 'process_alive', return_value=False), patch.object(call, 'context') as context:
            result = call.status('call-test-01')
            self.assertEqual(result['status'], 'ended')
            self.assertIsNone(result['invitation_performed'])
            context.assert_not_called()

    def test_resolve_cannot_hide_an_active_invitation(self):
        self.save(self.record('invitation_unknown'))
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=dict(self.idle(), incoming=[{}])):
            with self.assertRaisesRegex(ValueError, 'STILL_HAS'):
                call.resolve('call-test-01', True)
