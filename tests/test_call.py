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

    def selector_tree(self):
        return dict(complete=True, node_count=25, window_root='20',
                    cancel_count=1, cancel_caption_count=1, cancel_button='50',
                    nodes=[dict(name='selectedtitle', text='选择联系人'),
                           dict(name='searchedit', text=''),
                           dict(name='conversation_name', text='test group'),
                           dict(name='okbtn', text=''), dict(name='cancelbtn', text=''),
                           dict(name='checkbox', text=''), dict(name='checkbox', text='')])

    def test_member_selector_never_proves_a_call_or_selected_native_ids(self):
        tree = self.selector_tree()
        tree.update(outer_count=1, inner_count=1, accept_count=1, accept_button='30')
        tree['nodes'] += [dict(name='titletext', text='00:08'),
                          dict(name='middle_tips', text='已接通'),
                          dict(name='avatar_name', text='peer'),
                          dict(name='single_voip_tips', text='邀请你语音通话'),
                          dict(name='inviter_name', text='peer'),
                          dict(name='reject_btn', text='')]
        result = call.classify(self.prepared(), dict(kind='member_selector', hwnd='10', root='20'), tree)
        self.assertEqual(result['kind'], 'member_selector')
        self.assertEqual(result['visible_checkbox_count'], 2)
        for field in ('call_connection_verified', 'selector_purpose_verified',
                      'member_identity_verified', 'selection_verified'):
            self.assertFalse(result[field])
        self.assertNotIn('invitation_token', result)

    def selector(self):
        return call.classify(self.prepared(), dict(kind='member_selector', hwnd='10', root='20'),
                             self.selector_tree())

    def member_selector(self, selected=False, creation=False):
        tree = self.selector_tree()
        tree['nodes'] += [dict(name='', text='', pointer='60', control_type='WCheckbox',
                              user_data='456,0,;0,1,0' if creation else '456',
                              self_selected=selected)]
        if creation:
            tree['nodes'] = [dict(n, text='发起群聊') if n['name'] == 'selectedtitle' else n
                             for n in tree['nodes']]
        window = dict(kind='member_selector', hwnd='10', root='20',
                      selector_type='CSelectUserFrame2' if creation else 'CSelectUserFrame')
        return call.classify(self.prepared(), window, tree)

    def group_selector(self, chat='R:700'):
        tree = dict(self.selector_tree(), group_binding_verified=True, bound_group_chat=chat)
        tree['group_call_callback'] = dict(verified=True, object='80', chat_view='70',
                                           response_limit=100, response_flag=False)
        return call.classify(self.prepared(), dict(kind='member_selector', hwnd='10', root='20'), tree)

    def voice_origin_record(self, selector=None):
        selector = selector or self.group_selector()
        return dict(self.record(), intent=dict(operation='group_prepare', account='me', chat='R:700'),
                    chat_id='R:700', chat_view='70', status='member_selector_open',
                    normal_voice_entry_verified=True, group_call_callback=selector['group_call_callback'],
                    voice_origin_verified=True)

    def submission_selector(self, ids=None):
        return dict(self.group_selector(), native_selected_member_model_verified=True,
                    native_selected_member_ids=ids if ids is not None else ['456', '789'],
                    native_confirmation_control_verified=True,
                    confirmation_descriptor=dict(self.active()['handle'], ok_button='91',
                                                 common_view='92', buddy_list='93', ok_enabled=True))

    def test_group_submission_requires_the_entire_live_set_including_offscreen_members(self):
        selector = self.submission_selector()
        self.save(self.voice_origin_record(selector))
        live = dict(self.idle(), member_selectors=[selector])
        with patch.object(call, 'context', return_value=self.prepared()), patch.object(call, 'observe', return_value=live), patch.object(call, 'dispatch') as dispatch:
            for ids in (['456'], ['456', '789', '999'], ['456', '456'], [], ['0'], ['18446744073709551616']):
                with self.subTest(ids=ids), self.assertRaises(ValueError):
                    call.group_invite('call-test-01', ids, 'call-test-02')
                self.assertFalse(call.journal('call-test-02').exists())
            dispatch.assert_not_called()

    def test_group_submission_rejects_old_model_source_and_ambiguous_confirmation_context(self):
        tree = dict(self.selector_tree(), selected_member_model=dict(
            verified=True, source='classic_final_selection_vectors', ids=[], count=0,
            object_count=0, additional_count=0))
        window = dict(kind='member_selector', hwnd='10', root='20')
        with self.assertRaisesRegex(ValueError, 'INVALID_NATIVE_SELECTED_MEMBER_MODEL'):
            call.classify(self.prepared(), window, tree)
        tree['selected_member_model']['source'] = 'classic_live_buddy_selection'
        tree['selection_context'] = dict(verified=True, common_view='92', buddy_list='93', ok_button='91', ok_enabled=False)
        result = call.classify(self.prepared(), window, tree)
        self.assertTrue(result['native_confirmation_control_verified'])
        self.assertFalse(result['confirmation_descriptor']['ok_enabled'])
        for change in (dict(common_view='0'), dict(buddy_list=93), dict(ok_button='unknown'), dict(ok_enabled=1)):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'INVALID_NATIVE_SELECTION_CONTEXT'):
                call.classify(self.prepared(), window, dict(tree, selection_context=dict(tree['selection_context'], **change)))

    def test_group_submission_requires_original_voice_origin_and_enabled_confirmation(self):
        selector = self.submission_selector()
        for changed in (dict(selector, native_confirmation_control_verified=False),
                        dict(selector, confirmation_descriptor=dict(selector['confirmation_descriptor'], ok_enabled=False)),
                        dict(selector, native_selected_member_model_verified=False),
                        dict(selector, group_call_callback=dict(selector['group_call_callback'], object='81'))):
            self.save(self.voice_origin_record(selector))
            with self.subTest(changed=changed), patch.object(call, 'context', return_value=self.prepared()), patch.object(call, 'observe', return_value=dict(self.idle(), member_selectors=[changed])), patch.object(call, 'dispatch') as dispatch:
                with self.assertRaises(ValueError):
                    call.group_invite('call-test-01', ['456', '789'], 'call-test-02')
                dispatch.assert_not_called()
        self.save(dict(self.voice_origin_record(selector), normal_voice_entry_verified=False))
        with patch.object(call, 'context', return_value=self.prepared()), patch.object(call, 'observe', return_value=dict(self.idle(), member_selectors=[selector])), patch.object(call, 'dispatch') as dispatch:
            with self.assertRaises(ValueError):
                call.group_invite('call-test-01', ['456', '789'], 'call-test-02')
            dispatch.assert_not_called()

    def test_group_submission_is_durable_before_entry_and_button_return_never_proves_invitation(self):
        selector = self.submission_selector()
        self.save(self.voice_origin_record(selector))
        before = dict(self.idle(), member_selectors=[selector])
        calls = []
        def dispatch(prepared, mode, operation, window, payload):
            self.assertEqual(operation, 7)
            calls.append(mode)
            if mode == 1:
                self.assertFalse(call.journal('call-test-02').exists())
                return dict(ok=True), dict(group_submit_guard_verified=True)
            record = call.read_private(call.journal('call-test-02'))
            self.assertEqual(record['status'], 'group_submission_unknown')
            self.assertEqual(call.read_private(call.journal('call-test-01'))['submission_request_id'], 'call-test-02')
            self.assertEqual(record['expected_member_ids'], ['456', '789'])
            return dict(ok=True, state=2, native_action_entered=True), dict(activated=True)
        with patch.object(call, 'context', return_value=self.prepared()), patch.object(call, 'observe', side_effect=[before, dict(self.idle(), member_selectors=[])]), patch.object(call, 'dispatch', side_effect=dispatch), patch.object(call, 'desktop_session', return_value=nullcontext()):
            result = call.group_invite('call-test-01', ['789', '456'], 'call-test-02')
        self.assertEqual(calls, [1, 2])
        self.assertEqual(result['status'], 'group_submission_unknown')
        self.assertIsNone(result['invitation_performed'])
        self.assertFalse(result['call_connection_verified'])
        self.assertFalse(result['original_selector_open'])
        with patch.object(call, 'context') as context, patch.object(call, 'dispatch') as dispatch:
            self.assertTrue(call.group_invite('call-test-01', ['456', '789'], 'call-test-02')['replayed'])
            with self.assertRaisesRegex(ValueError, 'PAYLOAD_CONFLICT'):
                call.group_invite('call-test-01', ['456'], 'call-test-02')
            with self.assertRaisesRegex(ValueError, 'ALREADY_SUBMITTED'):
                call.group_invite('call-test-01', ['456', '789'], 'call-test-03')
            context.assert_not_called()
            dispatch.assert_not_called()

    def test_group_submission_preflight_failure_makes_no_journal_and_timeout_stays_unknown(self):
        selector = self.submission_selector()
        self.save(self.voice_origin_record(selector))
        live = dict(self.idle(), member_selectors=[selector])
        with patch.object(call, 'context', return_value=self.prepared()), patch.object(call, 'observe', return_value=live), patch.object(call, 'dispatch', return_value=(dict(ok=False, failure=119), None)):
            result = call.group_invite('call-test-01', ['456', '789'], 'call-test-02')
        self.assertFalse(result['invitation_performed'])
        self.assertFalse(call.journal('call-test-02').exists())
        with patch.object(call, 'context', return_value=self.prepared()), patch.object(call, 'observe', return_value=live), patch.object(call, 'dispatch', side_effect=[(dict(ok=True), dict(group_submit_guard_verified=True)), subprocess.TimeoutExpired('dispatch', 5)]), patch.object(call, 'desktop_session', return_value=nullcontext()):
            with self.assertRaises(subprocess.TimeoutExpired):
                call.group_invite('call-test-01', ['456', '789'], 'call-test-02')
        self.assertEqual(call.read_private(call.journal('call-test-02'))['status'], 'group_submission_unknown')
        self.assertEqual(call.read_private(call.journal('call-test-01'))['submission_request_id'], 'call-test-02')

    def test_group_submission_status_preserves_unknown_when_picker_has_closed(self):
        record = dict(self.record('group_submission_unknown'), intent={'operation': 'group_invite'},
                      selector_handle=self.active()['handle'], invitation_performed=None)
        with patch.object(call, 'observe', return_value=dict(self.idle(), member_selectors=[])):
            result = call.refresh(record, self.prepared())
        self.assertEqual(result['status'], 'group_submission_unknown')
        self.assertIsNone(result['invitation_performed'])
        self.assertFalse(result['call_connection_verified'])

    def test_shared_callback_requires_original_normal_voice_entry_journal(self):
        selector = self.group_selector()
        self.assertTrue(selector['native_group_call_callback_verified'])
        self.assertFalse(selector['selector_purpose_verified'])
        record = self.voice_origin_record(selector)
        bound = call.bind_voice_origin(record, selector)
        self.assertTrue(bound['selector_purpose_verified'])
        self.assertEqual(bound['voice_origin_request_id'], record['request_id'])
        for change in (dict(normal_voice_entry_verified=False), dict(chat_view='71'),
                       dict(status='ended'), dict(group_call_callback=None),
                       dict(intent=dict(operation='start', account='me', chat='R:700')),
                       dict(intent=dict(operation='group_prepare', account='other', chat='R:700')),
                       dict(intent=dict(operation='group_prepare', account='me', chat='R:701')),
                       dict(handle=dict(selector['handle'], root='21'))):
            with self.subTest(change=change):
                result = call.bind_voice_origin(dict(record, **change), selector)
                self.assertFalse(result['selector_purpose_verified'])
                self.assertIsNone(result['voice_origin_request_id'])
        old = dict(record)
        del old['group_call_callback']
        self.assertFalse(call.bind_voice_origin(old, selector)['selector_purpose_verified'])

    def test_native_callback_metadata_is_typed_and_never_proves_voice_alone(self):
        tree = dict(self.selector_tree(), group_binding_verified=True, bound_group_chat='R:700')
        callback = dict(verified=True, object='80', chat_view='70', response_limit=100, response_flag=False)
        window = dict(kind='member_selector', hwnd='10', root='20')
        for change in (dict(object='0'), dict(chat_view='xyz'), dict(response_limit=True),
                       dict(response_limit=2**32), dict(response_flag=0)):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'INVALID_NATIVE_GROUP_CALL_CALLBACK'):
                call.classify(self.prepared(), window, dict(tree, group_call_callback=dict(callback, **change)))
        for raw in (None, dict(callback, verified=1), dict(callback, verified=False)):
            result = call.classify(self.prepared(), window, dict(tree, group_call_callback=raw))
            self.assertFalse(result['native_group_call_callback_verified'])
            self.assertFalse(result['selector_purpose_verified'])

    def test_group_binding_requires_two_native_strings_and_changes_selector_token(self):
        first, second = self.group_selector(), self.group_selector('R:701')
        self.assertTrue(first['group_binding_verified'])
        self.assertEqual(first['bound_group_chat'], 'R:700')
        self.assertNotEqual(first['selector_token'], second['selector_token'])
        self.assertFalse(first['selector_purpose_verified'])
        for raw in ['S:123_456', 'R:１２３', 'R:', 'R:1"bad']:
            self.assertFalse(self.group_selector(raw)['group_binding_verified'])

    def test_native_selected_model_includes_offscreen_ids_without_proving_invitation(self):
        tree = self.selector_tree()
        tree['nodes'] += [dict(pointer='60', control_type='WCheckbox', user_data='456', self_selected=True)]
        tree['selected_member_model'] = dict(verified=True, source='classic_live_buddy_selection',
                                            ids=['456', '789'], count=2, object_count=2, additional_count=0)
        result = call.classify(self.prepared(), dict(kind='member_selector', hwnd='10', root='20'), tree)
        self.assertEqual(result['selected_visible_member_ids'], ['456'])
        self.assertEqual(result['native_selected_member_ids'], ['456', '789'])
        self.assertTrue(result['native_selected_member_model_verified'])
        for field in ('selection_verified', 'selector_purpose_verified', 'call_connection_verified'):
            self.assertFalse(result[field])
        empty = dict(verified=True, source='classic_live_buddy_selection', ids=[], count=0,
                     object_count=0, additional_count=0)
        result = call.classify(self.prepared(), dict(kind='member_selector', hwnd='10', root='20'),
                               dict(self.selector_tree(), selected_member_model=empty))
        self.assertTrue(result['native_selected_member_model_verified'])
        self.assertEqual(result['native_selected_member_ids'], [])
        creation = dict(kind='member_selector', hwnd='10', root='20', selector_type='CSelectUserFrame2')
        tree = self.selector_tree()
        tree['nodes'] = [dict(n, text='发起群聊') if n['name'] == 'selectedtitle' else n for n in tree['nodes']]
        result = call.classify(self.prepared(), creation, dict(tree, selected_member_model=empty))
        self.assertFalse(result['native_selected_member_model_verified'])
        self.assertIsNone(result['native_selected_member_ids'])

    def test_native_model_disagreement_invalid_ids_and_unknown_layout_are_not_trusted(self):
        tree = self.selector_tree()
        tree['nodes'] += [dict(pointer='60', control_type='WCheckbox', user_data='456', self_selected=False)]
        model = dict(verified=True, source='classic_live_buddy_selection', ids=['456'], count=1,
                     object_count=1, additional_count=0)
        window = dict(kind='member_selector', hwnd='10', root='20')
        with self.assertRaisesRegex(ValueError, 'DISAGREES_WITH_VISIBLE'):
            call.classify(self.prepared(), window, dict(tree, selected_member_model=model))
        for change in (dict(ids=['0']), dict(ids=['18446744073709551616']), dict(count=True),
                       dict(ids=['789', '789'], count=2), dict(source='creation_layout'),
                       dict(object_count=2), dict(ids=['７８９'])):
            with self.assertRaisesRegex(ValueError, 'INVALID_NATIVE_SELECTED'):
                call.classify(self.prepared(), window, dict(tree, selected_member_model=dict(model, **change)))
        for raw in (None, dict(verified=False), dict(model, verified=1)):
            result = call.classify(self.prepared(), window, dict(tree, selected_member_model=raw))
            self.assertFalse(result['native_selected_member_model_verified'])
            self.assertIsNone(result['native_selected_member_ids'])

    def group_preparation_patches(self, native):
        selector = self.group_selector()
        return (patch.object(call, 'context', side_effect=self.prepared),
                patch.object(call, 'prepare_view', side_effect=lambda p: dict(p, width=0x70)),
                patch.object(call, 'observe', side_effect=[self.idle(), dict(self.idle(), member_selectors=[selector])]),
                patch.object(call, 'warm'), patch.object(call, 'desktop_session', side_effect=nullcontext),
                patch.object(call, 'dispatch', side_effect=native))

    def test_group_preparation_journals_before_entry_and_replay_never_reopens(self):
        from contextlib import ExitStack
        def native(p, mode, operation=0):
            self.assertEqual(operation, 6)
            if mode == 2:
                value=json.loads(call.journal('call-test-01').read_text())
                self.assertEqual(value['status'], 'group_prepare_unknown')
                self.assertFalse(value['invitation_performed'])
            return dict(ok=True), {}
        with ExitStack() as stack:
            mocks=[stack.enter_context(p) for p in self.group_preparation_patches(native)]
            result=call.group_prepare('me','R:700','call-test-01')
            self.assertTrue(result['ok'])
            self.assertEqual(result['status'],'member_selector_open')
            self.assertFalse(result['invitation_performed'])
            self.assertTrue(result['voice_origin_verified'])
            self.assertTrue(result['selector']['selector_purpose_verified'])
            self.assertTrue(call.group_prepare('me','R:700','call-test-01')['replayed'])
            with self.assertRaisesRegex(ValueError,'PAYLOAD_CONFLICT'):
                call.group_prepare('me','R:701','call-test-01')
            self.assertEqual(sum(c.args[1] == 2 for c in mocks[-1].call_args_list),1)

    def test_group_preparation_timeout_is_unknown_and_blocks_new_request(self):
        from contextlib import ExitStack
        def native(p,mode,operation=0):
            if mode==2:raise subprocess.TimeoutExpired('hook',30)
            return dict(ok=True),{}
        with ExitStack() as stack:
            [stack.enter_context(p) for p in self.group_preparation_patches(native)]
            with self.assertRaises(subprocess.TimeoutExpired):call.group_prepare('me','R:700','call-test-01')
        value=json.loads(call.journal('call-test-01').read_text())
        self.assertEqual(value['status'],'group_prepare_unknown')
        with self.assertRaisesRegex(ValueError,'OUTCOME_UNKNOWN'):call.block_unresolved(self.prepared())

    def test_group_preparation_unverified_callback_stays_unknown_and_is_not_reopened(self):
        from contextlib import ExitStack
        selector = dict(self.group_selector(), native_group_call_callback_verified=False, group_call_callback=None)
        with ExitStack() as stack:
            mocks = [stack.enter_context(p) for p in self.group_preparation_patches(lambda *a, **k: (dict(ok=True), {}))]
            mocks[2].side_effect = [self.idle(), dict(self.idle(), member_selectors=[selector])]
            with self.assertRaisesRegex(ValueError, 'EXACT_GROUP_CALL_CALLBACK_NOT_VERIFIED_RESULT_UNKNOWN'):
                call.group_prepare('me', 'R:700', 'call-test-01')
            replay = call.group_prepare('me', 'R:700', 'call-test-01')
        self.assertEqual(replay['status'], 'group_prepare_unknown')
        self.assertTrue(replay['read_only'])
        self.assertFalse(replay['invitation_performed'])
        self.assertEqual(sum(c.args[1] == 2 for c in mocks[-1].call_args_list), 1)

    def test_group_preparation_request_tracks_selector_not_active_call(self):
        selector=self.group_selector();record=dict(self.record(),intent={'operation':'group_prepare'},
                                                 chat_id='R:700',status='member_selector_open')
        with patch.object(call,'observe',return_value=dict(self.idle(),member_selectors=[selector])):
            current=call.refresh(record,self.prepared())
        self.assertEqual(current['status'],'member_selector_open')
        self.assertTrue(current['current_selector_matches'])
        self.assertFalse(current['call_connection_verified'])
        self.assertFalse(current['voice_origin_verified'])
        with patch.object(call,'observe',return_value=dict(self.idle(),member_selectors=[self.group_selector('R:701')])):
            with self.assertRaisesRegex(ValueError,'SELECTOR_BINDING_CHANGED'):
                call.refresh(record,self.prepared())
        with patch.object(call,'observe',return_value=self.idle(self.active())):
            closed=call.refresh(record,self.prepared())
        self.assertEqual(closed['status'],'ended')
        self.assertTrue(closed['selector_closed_observed'])
        self.save(record)
        with self.assertRaisesRegex(ValueError,'USE_SELECTOR_CANCEL'):call.hangup('call-test-01')

    def test_original_group_voice_callback_change_is_rejected_and_close_clears_live_origin(self):
        selector = self.group_selector()
        record = self.voice_origin_record(selector)
        for callback in (None, dict(selector['group_call_callback'], object='81'),
                         dict(selector['group_call_callback'], chat_view='71'),
                         dict(selector['group_call_callback'], response_limit=0),
                         dict(selector['group_call_callback'], response_flag=True)):
            changed = dict(selector, group_call_callback=callback)
            with self.subTest(callback=callback), patch.object(call, 'observe', return_value=dict(self.idle(), member_selectors=[changed])):
                with self.assertRaisesRegex(ValueError, 'ORIGINAL_GROUP_VOICE_ORIGIN_CHANGED'):
                    call.refresh(record, self.prepared())
        with patch.object(call, 'observe', return_value=self.idle()):
            closed = call.refresh(record, self.prepared())
        self.assertEqual(closed['status'], 'ended')
        self.assertFalse(closed['voice_origin_verified'])
        self.save(record)
        with patch.object(call, 'process_alive', return_value=False), patch.object(call, 'context') as context:
            ended = call.status(record['request_id'])
        self.assertFalse(ended['voice_origin_verified'])
        self.assertEqual(ended['status'], 'ended')
        context.assert_not_called()

    def test_individual_metadata_does_not_convert_departments_or_unknown_formats_to_members(self):
        nodes = [dict(pointer='60', control_type='WCheckbox', self_selected=False, user_data=data)
                 for data in ['456,0,;2,0', '456,0,;0,0,0', '456', '0,0,;0,1,0',
                              '18446744073709551616,0,;0,1,0']]
        self.assertEqual(call.selector_members('CSelectUserFrame2', nodes), [])
        own = self.member_selector(True, True)
        self.assertEqual(own['visible_members'][0]['native_id'], '456')
        self.assertEqual(own['selected_visible_member_ids'], ['456'])
        self.assertFalse(own['full_member_list_verified'])
        self.assertFalse(own['selector_purpose_verified'])
        self.assertFalse(own['selection_verified'])
        self.assertFalse(own['call_connection_verified'])

    def test_duplicate_native_member_identity_is_rejected(self):
        node = dict(pointer='60', control_type='WCheckbox', self_selected=False, user_data='456')
        with self.assertRaisesRegex(ValueError, 'AMBIGUOUS_MEMBER'):
            call.selector_members('CSelectUserFrame', [node, dict(node, pointer='61')])

    def test_creation_picker_token_and_title_cannot_be_interchanged_with_voice_picker(self):
        creation = self.member_selector(creation=True)
        self.assertNotEqual(creation['selector_token'], self.member_selector()['selector_token'])
        tree = self.selector_tree()
        with self.assertRaisesRegex(ValueError, 'COMPLETE_MEMBER_SELECTOR'):
            call.classify(self.prepared(), dict(kind='member_selector', hwnd='10', root='20',
                                               selector_type='CSelectUserFrame2'), tree)

    def test_selector_selection_binds_checkbox_metadata_previous_and_desired_state(self):
        import struct
        for creation in (False, True):
            selector = self.member_selector(creation=creation)
            before = dict(self.idle(), member_selectors=[selector])
            after = dict(self.idle(), member_selectors=[self.member_selector(True, creation)])
            with patch.object(call, 'context', side_effect=self.prepared), \
                 patch.object(call, 'observe', side_effect=[before, after]), \
                 patch.object(call, 'desktop_session', side_effect=nullcontext), \
                 patch.object(call, 'dispatch', return_value=({'ok': True}, {'activated': True})) as dispatch:
                result = call.selector_select('me', selector['selector_token'], '456', True)
                self.assertTrue(result['ok'])
                self.assertTrue(result['selection_change_observed'])
                self.assertFalse(result['invitation_performed'])
                self.assertEqual(dispatch.call_count, 1)
                args = dispatch.call_args.args
                self.assertEqual(args[1:3], (2, 5))
                data = '456,0,;0,1,0' if creation else '456'
                self.assertEqual(args[4], struct.pack('<IIII', 0x20, 0x60, 0, 1) +
                                 data.encode('utf-16-le') + b'\0\0')

    def test_selector_selection_replay_or_missing_visible_member_never_toggles(self):
        selector = self.member_selector(True)
        live = dict(self.idle(), member_selectors=[selector])
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=live), patch.object(call, 'dispatch') as dispatch:
            result = call.selector_select('me', selector['selector_token'], '456', True)
            self.assertTrue(result['read_only'])
            with self.assertRaisesRegex(ValueError, 'ONE_VISIBLE_NATIVE_MEMBER'):
                call.selector_select('me', selector['selector_token'], '457', False)
            with self.assertRaisesRegex(ValueError, 'EXACT_MEMBER_SELECTOR'):
                call.selector_select('me', 'b' * 64, '456', False)
            dispatch.assert_not_called()

    def test_checkbox_activation_without_observed_change_is_not_success_or_retried(self):
        selector = self.member_selector()
        live = dict(self.idle(), member_selectors=[selector])
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=live), \
             patch.object(call, 'desktop_session', side_effect=nullcontext), \
             patch.object(call, 'dispatch', return_value=({'ok': True}, {'activated': True})) as dispatch:
            result = call.selector_select('me', selector['selector_token'], '456', True)
            self.assertFalse(result['ok'])
            self.assertFalse(result['automatic_retry_allowed'])
            self.assertEqual(dispatch.call_count, 1)

    def test_cancel_token_binds_current_window_button_caption_and_account(self):
        original = self.selector()
        window = dict(kind='member_selector', hwnd='10', root='20')
        changed_button = call.classify(self.prepared(), window, dict(self.selector_tree(), cancel_button='51'))
        changed_window = call.classify(self.prepared(), dict(window, hwnd='11'), self.selector_tree())
        changed_scope = self.prepared()
        changed_scope['value'] = dict(changed_scope['value'], scope='other-account')
        other_account = call.classify(changed_scope, window, self.selector_tree())
        self.assertEqual(len({x['selector_token'] for x in [original, changed_button, changed_window, other_account]}), 4)
        untyped = call.classify(self.prepared(), window, dict(self.selector_tree(), cancel_count=0))
        self.assertFalse(untyped['cancel_control_verified'])
        self.assertNotIn('selector_token', untyped)

    def test_stale_selector_token_cannot_cancel_another_picker(self):
        live = dict(self.idle(), member_selectors=[self.selector()])
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=live), patch.object(call, 'dispatch') as dispatch:
            with self.assertRaisesRegex(ValueError, 'EXACT_MEMBER_SELECTOR'):
                call.selector_cancel('me', 'b' * 64)
            dispatch.assert_not_called()

    def test_selector_cancel_activates_only_bound_cancel_and_requires_observed_close(self):
        import struct
        selected = self.selector()
        live = dict(self.idle(), member_selectors=[selected])
        for after, closed in [(self.idle(), True), (live, False)]:
            with patch.object(call, 'context', side_effect=self.prepared), \
                 patch.object(call, 'observe', side_effect=[live, after]), \
                 patch.object(call, 'desktop_session', side_effect=nullcontext), \
                 patch.object(call, 'dispatch', return_value=({'ok': True}, {'activated': True})) as dispatch:
                result = call.selector_cancel('me', selected['selector_token'])
                self.assertEqual(result['ok'], closed)
                self.assertEqual(result['selector_closed_observed'], closed)
                self.assertFalse(result['invitation_performed'])
                self.assertFalse(result['automatic_retry_allowed'])
                args = dispatch.call_args.args
                self.assertEqual(args[1:3], (2, 3))
                self.assertEqual(args[4], struct.pack('<III', 0x20, 0x50, 0))
                self.assertEqual(dispatch.call_count, 1)

    def test_selector_cancel_timeout_never_retries_native_activation(self):
        selected = self.selector()
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=dict(self.idle(), member_selectors=[selected])), \
             patch.object(call, 'desktop_session', side_effect=nullcontext), \
             patch.object(call, 'dispatch', side_effect=subprocess.TimeoutExpired('hook', 30)) as dispatch:
            with self.assertRaises(subprocess.TimeoutExpired):
                call.selector_cancel('me', selected['selector_token'])
            self.assertEqual(dispatch.call_count, 1)

    def test_member_selector_requires_complete_bound_window_and_unique_controls(self):
        window = dict(kind='member_selector', hwnd='10', root='20')
        good = self.selector_tree()
        for tree in [dict(good, complete=False), dict(good, window_root='21'),
                     dict(good, nodes=good['nodes'][1:]),
                     dict(good, nodes=good['nodes'] + [dict(name='cancelbtn', text='')])]:
            with self.assertRaises(ValueError):
                call.classify(self.prepared(), window, tree)

    def test_observe_reports_member_selector_separately_from_calls(self):
        prepared = dict(self.prepared(), resolution=dict(tid=12))
        window = dict(kind='member_selector', hwnd='10', root='20', tid=12)
        with patch.object(call, 'probe', return_value=[window, dict(identity_unchanged=True)]), \
             patch.object(call, 'dispatch', return_value=({'ok': True}, self.selector_tree())):
            result = call.observe(prepared)
        self.assertEqual(len(result['member_selectors']), 1)
        self.assertIsNone(result['active'])
        self.assertEqual(result['incoming'], [])
        self.assertFalse(result['call_connection_verified'])

    def test_open_member_selector_blocks_new_start_before_journal_or_target_preparation(self):
        live = dict(self.idle(), member_selectors=[dict(kind='member_selector')])
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=live), \
             patch.object(call, 'prepare_start') as prepare, patch.object(call, 'dispatch') as dispatch:
            with self.assertRaisesRegex(ValueError, 'MEMBER_SELECTOR_OPEN'):
                call.start('me', 'S:123_456', 'call-test-01')
            prepare.assert_not_called();dispatch.assert_not_called()
            self.assertFalse(call.journal('call-test-01').exists())

    def test_open_member_selector_blocks_acceptance_and_target_preflight(self):
        live = dict(self.idle(), member_selectors=[{}], incoming=[dict(invitation_token='a' * 64)])
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=live), patch.object(call, 'warm'), \
             patch.object(call, 'prepare_start') as prepare, patch.object(call, 'dispatch') as dispatch:
            with self.assertRaisesRegex(ValueError, 'MEMBER_SELECTOR_OPEN'):
                call.answer('me', 'a' * 64, 'call-test-01')
            with self.assertRaisesRegex(ValueError, 'MEMBER_SELECTOR_OPEN'):
                call.preflight('me', 'S:123_456')
            prepare.assert_not_called();dispatch.assert_not_called()
            self.assertFalse(call.journal('call-test-01').exists())

    def test_resolve_does_not_hide_an_unclosed_member_selector(self):
        self.save(self.record('invitation_unknown'))
        live = dict(self.idle(), member_selectors=[{}])
        with patch.object(call, 'context', side_effect=self.prepared), \
             patch.object(call, 'observe', return_value=live):
            with self.assertRaisesRegex(ValueError, 'STILL_HAS'):
                call.resolve('call-test-01', True)
        self.assertEqual(json.loads(call.journal('call-test-01').read_text())['status'], 'invitation_unknown')

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
