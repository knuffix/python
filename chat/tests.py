import unittest
import re
import chat
import os
from mock import patch, mock_open
IP4_RE = re.compile(
    r'^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$'
)


class Tests(unittest.TestCase):
    @patch('chat.socket.socket')
    def setUp(self, msock):
        self.program = chat.Program('test', 123, 'nick')
        self.msock = msock

    def test_getlanip(self):
        ip = self.program.get_lan_ip()
        ip = re.match(IP4_RE, ip).group(0)
        self.assertTrue(ip, True)

    def test_kick(self):
        self.program.kick_client('asd')
        self.assertEqual({},self.program.connected)

    def test_mute(self):
        last_len = chat.PIPE.qsize()
        self.program.mute_client('asd')
        self.assertEqual(chat.PIPE.qsize(), last_len + 1)

    def test_recieved_pm(self):
        last_len = chat.PIPE.qsize()
        self.program.recieved_pm('123', ('test', 123))
        self.assertEqual(chat.PIPE.qsize(), last_len)

    def test_change_status(self):
        self.program.change_status('kick', ('test', 123))
        self.assertEqual(len(self.program.connected), 0)

    def test_change_status2(self):
        self.program.change_status('mute', ('test', 123))
        self.assertEqual(self.program.muted, True)

    def test_change_status3(self):
        self.program.change_status('unmute', ('test', 123))
        self.assertEqual(self.program.muted, False)

    def test_unmute_client(self):
        last_len = chat.PIPE.qsize()
        self.program.unmute_client('test')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_send_pm(self):
        last_len = chat.PIPE.qsize()
        self.program.send_pm('test', 'test')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_system_message(self):
        last_len = chat.PIPE.qsize()
        self.program.system_message('kick', ('test', 123))
        self.assertEqual(chat.PIPE.qsize(), last_len)

    def test_connect_to(self):
        last_len = chat.PIPE.qsize()
        self.program.connect_to('127.0.0.1',12345)
        self.assertEqual(chat.PIPE.qsize(),last_len +1)

    def test_simple_message(self):
        last_len = chat.PIPE.qsize()
        self.program.simple_message('nick', ('test',12345))
        self.assertEqual(chat.PIPE.qsize(), last_len)

    def test_disconnect(self):
        last_len = chat.PIPE.qsize()
        self.program.disconnect()
        self.assertEqual(chat.PIPE.qsize(),last_len +1)

    def test_add_to_network(self):
        last_len = chat.PIPE.qsize()
        self.program.add_to_network('test1', ('8.8.8.8', 12345))
        self.assertEqual(chat.PIPE.qsize(),last_len +2)

    def test_delete_client(self):
        last_len = chat.PIPE.qsize()
        self.program.delete_client('', ('127.0.0.1', 12345))
        self.assertEqual(chat.PIPE.qsize(),last_len)

    def test_send_file(self):
        last_len = chat.PIPE.qsize()
        self.program.send_file('file', 'nick')
        self.assertEqual(chat.PIPE.qsize(),last_len +1)

    def test_recieve_filename(self):
        last_len = chat.PIPE.qsize()
        self.program.recieve_filename(b'2135', ('127.0.0.1',21355))
        self.assertEqual(chat.PIPE.qsize(),last_len)

    def test_send_msg(self):
        last_len = chat.PIPE.qsize()
        self.program.send_msg('213')
        self.assertEqual(chat.PIPE.qsize(), last_len)

    def test_send(self):
        self.program.add_to_network('test', ('127.1.1.1', 13337))
        self.program.send_msg('abcd')
        self.msock().sendto.assert_called_with(b'0abcd', ('127.1.1.1', 13337))

    def test_send_muted(self):
        last_len = chat.PIPE.qsize()
        self.program.muted = True
        #self.program.add_to_network('test', ('127.1.1.1', 13337))
        self.program.send_msg('abcd')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)
        #self.msock().sendto.assert_called_with(b'0abcd', ('127.1.1.1', 13337))

    def test_send_command(self):
        last_len = chat.PIPE.qsize()
        self.program.send_msg('/kick')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_connect_to_send(self):
        self.program.connect_to('127.1.1.1', '13337')
        self.msock().sendto.assert_called_with(b'1nick', ('127.1.1.1', 13337))

    def test_kick_client_send(self):
        self.program.add_to_network('test', ('127.1.1.1', 13337))
        self.program.kick_client('test')
        self.msock().sendto.assert_called_with(b'4 You\'re kicked', ('127.1.1.1', 13337))

    def test_kick_client_fail(self):
        last_len = chat.PIPE.qsize()
        self.program.kick_client('test')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_kick_client_fail2(self):
        last_len = chat.PIPE.qsize()
        self.program.kick_client('123')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_mute_client_send(self):
        self.program.add_to_network('test', ('127.1.1.1', 13337))
        self.program.mute_client('test')
        self.msock().sendto.assert_called_with(b'4 You\'re muted', ('127.1.1.1', 13337))

    def test_mute_client_fail(self):
        last_len = chat.PIPE.qsize()
        self.program.add_to_network('test', ('127.1.1.1', 13337)) #+2
        self.program.mute_client('nick') #+1
        self.assertEqual(chat.PIPE.qsize(), last_len+3)

    def test_mute_client_fail2(self):
        last_len = chat.PIPE.qsize()
        self.program.add_to_network('test', ('127.1.1.1', 13337)) #+2
        self.program.mute_client('123') #+1
        self.assertEqual(chat.PIPE.qsize(), last_len+3)

    def test_unmute_client_send(self):
        self.program.add_to_network('test', ('127.1.1.1', 13337))
        self.program.mute_client('test')
        self.program.unmute_client('test')
        self.msock().sendto.assert_called_with(b'4 You\'re unmuted', ('127.1.1.1', 13337))

    def test_unmute_client_send2(self):
        last_len = chat.PIPE.qsize()
        self.program.add_to_network('test', ('127.1.1.1', 13337)) #+2
        self.program.mute_client('test') #+1
        self.program.unmute_client('test123123') #+1
        self.assertEqual(chat.PIPE.qsize(), last_len+4)

    def test_send_pm_send(self):
        self.program.add_to_network('test', ('127.1.1.1', 13337))
        self.program.send_pm('test', 'test')
        self.msock().sendto.assert_called_with(b'6test', ('127.1.1.1', 13337))

    def test_send_pm_send_fail(self):
        last_len = chat.PIPE.qsize()
        self.program.add_to_network('test', ('127.1.1.1', 13337)) #+2
        self.program.send_pm('test123', 'test123') #+1
        self.assertEqual(chat.PIPE.qsize(), last_len+3)

    def test_connect_to_fail(self):
        last_len = chat.PIPE.qsize()
        self.program.connect_to('', '13337')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_connect_to_fail2(self):
        last_len = chat.PIPE.qsize()
        self.program.connect_to('111', '13337')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_connect_to_fail3(self):
        last_len = chat.PIPE.qsize()
        self.program.connect_to('111', 'asd')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_connect_to_fail4(self):
        last_len = chat.PIPE.qsize()
        self.program.connect_to('111', '{}'.format(self.program.addr[1]))
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_connect_to_fail5(self):
        last_len = chat.PIPE.qsize()
        self.program.add_to_network('test', ('127.1.1.1', 13337)) #+2
        self.program.connect_to('127.1.1.1', '13337')#+1
        self.assertEqual(chat.PIPE.qsize(), last_len+3)

    def test_disconnect_send(self):
        self.program.add_to_network('test', ('127.1.1.1', 13337))
        self.program.disconnect()
        self.msock().sendto.assert_called_with(b'3', ('127.1.1.1', 13337))

    def test_disconnect_send_fail(self):
        last_len = chat.PIPE.qsize()
        self.program.disconnect()
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_delete_client2(self):
        last_len = chat.PIPE.qsize()
        self.program.add_to_network('test', ('127.1.1.1', 13337)) #+2
        self.program.delete_client('', ('127.1.1.1', 13337)) #+2
        self.assertEqual(chat.PIPE.qsize(), last_len+4)

    def test_recieve_filename_fail(self):
        last_len = chat.PIPE.qsize()
        self.program.recieve_filename('', ('127.1.1.1', 13337))
        self.assertEqual(chat.PIPE.qsize(), last_len)

    def test_commands_rec(self):
        last_len = chat.PIPE.qsize()
        self.program.send_msg('/213')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_commands_rec2(self):
        last_len = chat.PIPE.qsize()
        self.program.send_msg('/kick')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_commands_rec3(self):
        last_len = chat.PIPE.qsize()
        self.program.send_msg('/pm nick 123')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_send_file_fail(self):
        last_len = chat.PIPE.qsize()
        self.program.send_file('file', None)
        self.assertEqual(chat.PIPE.qsize(), last_len+1)

    def test_send_file_fail2(self):
        last_len = chat.PIPE.qsize()
        self.program.send_file('file', '123')
        self.assertEqual(chat.PIPE.qsize(), last_len+1)
if __name__ == "__main__":
    unittest.main()