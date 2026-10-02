import base64
import hashlib
import json
import sqlite3
import subprocess
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

import test_messages
from test_media import length_field
from wecom_linux_cli import sending, sending_cards as cards
from wecom_linux_cli.messages import account


def article():
    return length_field(1, b'https://example.com/article') + length_field(3, '中文标题'.encode()) + length_field(4, b'') + length_field(7, b'opaque thumbnail upload metadata')


def mini():
    inner = (length_field(1, b'gh_actual@app') + length_field(2, b'wx_actual') +
             length_field(3, b'/actual/page') + b'\x20\x02' + length_field(7, '小程序'.encode()) +
             length_field(8, b'description') + length_field(10, b'app name') + length_field(23, b'opaque resource'))
    return length_field(107, inner)


class CardXmlTests(unittest.TestCase):
    def test_article_and_miniprogram_roundtrip_preserve_unknown_fields(self):
        for kind, raw in ((13, article()), (78, mini())):
            with self.subTest(kind=kind):
                actual_kind, actual = cards.parse_xml(cards._xml(kind, raw).encode())
                self.assertEqual(actual_kind, kind)
                self.assertEqual(cards.fields(actual), cards.fields(raw))

    def test_modified_titles_descriptions_and_unknown_native_fields(self):
        for kind, raw, title_number, desc_number in ((13, article(), 3, 4), (78, mini(), 7, 8)):
            root = ET.fromstring(cards._xml(kind, raw))
            root.find('appmsg/title').text = '修改标题 ✅'
            root.find('appmsg/des').text = '中文\n第二行'
            actual_kind, actual = cards.parse_xml(ET.tostring(root))
            parsed = cards._body(actual_kind, actual)
            self.assertEqual(cards._one(parsed, title_number).decode(), '修改标题 ✅')
            self.assertEqual(cards._one(parsed, desc_number).decode(), '中文\n第二行')
            self.assertEqual(cards._one(parsed, 7 if kind == 13 else 23), b'opaque thumbnail upload metadata' if kind == 13 else b'opaque resource')

    def test_plain_link_xml_is_native_card_but_mini_needs_actual_resource(self):
        kind, raw = cards.parse_xml(b'<msg><appmsg><type>5</type><title>card</title><url>https://example.com</url></appmsg></msg>')
        self.assertEqual(kind, 13)
        self.assertEqual(cards._one(cards.fields(raw), 3), b'card')
        with self.assertRaisesRegex(ValueError, 'EXPORTED_NATIVE'):
            cards.parse_xml(b'<msg><appmsg><type>33</type><title>mini</title></appmsg></msg>')

    def test_dtd_utf8_limits_duplicates_and_corrupt_payload_rejected(self):
        valid = cards._xml(13, article()).encode()
        for invalid in (b'', valid + b'\0', b'\xff', b'x' * 65537,
                        b'<!DOCTYPE msg [<!ENTITY x "x">]>' + valid,
                        valid.replace(b'<title>', b'<title>x</title><title>'),
                        valid.replace(b'content-type="13"', b'content-type="78"'),
                        valid.replace(b'encoding="base64"', b'encoding="hex"'),
                        valid.replace(hashlib.sha256(article()).hexdigest().encode(), b'0' * 64)):
            with self.subTest(invalid=invalid[:50]), self.assertRaises(ValueError):
                cards.parse_xml(invalid)
        with self.assertRaisesRegex(ValueError, 'AMBIGUOUS'):
            cards._body(13, article() + length_field(3, b'duplicate'))

    def test_miniprogram_identity_cannot_reuse_other_apps_resource(self):
        root = ET.fromstring(cards._xml(78, mini()))
        root.find('appmsg/weappinfo/appid').text = 'another-app'
        with self.assertRaisesRegex(ValueError, 'ACTUAL_SOURCE'):
            cards.parse_xml(ET.tostring(root))


class CardSendTests(unittest.TestCase):
    setUp = test_messages.MessageReadTests.setUp
    tearDown = test_messages.MessageReadTests.tearDown

    def prepared(self, name, chat, kind, raw):
        return {'value': account(name), 'chat': 'R:test', 'before': [{'pid': 123}],
                'payload': raw, 'input_kind': kind}

    def dispatched(self, prepared, mode):
        record = json.loads(sending._journal('card-test-01').read_text())
        self.assertEqual(record['status'], 'submission_unknown')
        self.assertFalse(record['automatic_retry_allowed'])
        with sqlite3.connect(self.data / 'message.db') as conn:
            conn.execute('INSERT INTO message_table VALUES(46,987,123,?,13,101,?)',
                         (prepared['chat'], prepared['payload']))
        return {'ok': True, 'state': 2, 'native_send_entered': True,
                'send_returned': True, 'ids': [1, 0, 46, 0]}, b''

    def test_replay_changed_source_action_xml_and_target_conflict(self):
        source = {'account_scope': account('me')['scope'], 'chat_id': 'R:source', 'message_id': 1}
        with patch.object(cards, '_prepare', side_effect=self.prepared), \
             patch.object(cards, '_check', return_value={'ok': True}), \
             patch.object(sending, '_dispatch', side_effect=self.dispatched) as dispatch:
            result = cards._send('me', 'R:test', 13, article(), 'card-test-01', 'forward', source)
            self.assertTrue(result['ok'])
            self.assertTrue(cards._send('me', 'R:test', 13, article(), 'card-test-01', 'forward', source)['replayed'])
            for raw, action, identity, target in ((mini(), 'forward', source, 'R:test'),
                                                 (article(), 'xml', source, 'R:test'),
                                                 (article(), 'forward', source | {'message_id': 2}, 'R:test'),
                                                 (article(), 'forward', source, 'R:other')):
                with self.assertRaisesRegex(ValueError, 'PAYLOAD_CONFLICT'):
                    cards._send('me', target, 13, raw, 'card-test-01', action, identity)
            self.assertEqual(dispatch.call_count, 1)

    def test_unknown_alias_and_action_do_not_resubmit(self):
        source = {'message_id': 1}
        with patch.object(cards, '_prepare', side_effect=self.prepared), \
             patch.object(cards, '_check', return_value={'ok': True}), \
             patch.object(sending, '_dispatch', side_effect=subprocess.TimeoutExpired('helper', 30)) as dispatch:
            self.assertEqual(cards._send('me', 'R:test', 13, article(), 'card-test-01', 'forward', source)['status'], 'submission_unknown')
            self.assertTrue(cards._send('me', 'R:test', 13, article(), 'card-test-01', 'forward', source)['replayed'])
            with self.assertRaisesRegex(ValueError, 'QUERY_ORIGINAL'):
                cards._send('me', 'complete unique name', 13, article(), 'card-test-02', 'xml', source)
            self.assertEqual(dispatch.call_count, 1)

    def test_exact_source_chat_required_and_unsupported_kind_rejected(self):
        with sqlite3.connect(self.data / 'message.db') as conn:
            conn.execute('UPDATE message_table SET content_type=13,content=? WHERE message_id=45', (article(),))
        self.assertEqual(cards.message_xml('me', 'R:test', 45)['content_type'], 13)
        with self.assertRaisesRegex(ValueError, 'SOURCE_MESSAGE_NOT_FOUND'):
            cards.message_xml('me', 'R:other', 45)
        with self.assertRaisesRegex(ValueError, 'CARD_REQUIRED'):
            cards._body(2, article())

    def test_null_wrong_kind_or_changed_miniprogram_not_verified(self):
        for kind, raw in ((13, article()), (78, mini())):
            record = {'card': {'content_type': kind, 'payload': base64.b64encode(raw).decode()}}
            self.assertTrue(cards.card_matches(kind, raw, record))
            self.assertFalse(cards.card_matches(2, raw, record))
            self.assertFalse(cards.card_matches(kind, b'', record))
        with sqlite3.connect(self.data / 'message.db') as conn:
            conn.execute('UPDATE message_table SET content_type=13,content=NULL WHERE message_id=45')
        record = {'account': 'me', 'account_scope': account('me')['scope'], 'chat_id': 'R:test',
                  'media_kind': 'card', 'card': {'content_type': 13, 'payload': base64.b64encode(article()).decode()},
                  'local_message_id': 45, 'status': 'submission_unknown', 'ok': False}
        self.assertFalse(sending._reconcile(record)['ok'])
