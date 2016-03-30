import unittest
from mock import patch, Mock
import ntp
import struct

class ntp_test(unittest.TestCase):
    @patch('ntp.socket.socket')
    def setUp(self, msock):
        self.program = ntp.ntpClient(False, 10, 3)
        self.msock = msock
        ntp.select.select = Mock()
        ntp.select.select.return_value = ([msock], [msock], [], 3)
        self.data = struct.pack('!12I', 2208988800,2208988800,2208988800,
                                2208988800,2208988800,2208988800
                           ,2208988800,2208988800,2208988800,
                                2208988800,2208988800,2208988800)
    def test_make_buf(self):
        self.program.make_buf()
        shift = 2 << 3
        shift |= 3
        buf = struct.pack('!BBBbIIIQQQQ', shift, 0,0,0,0,0,0,0,0,0,0)
        self.assertEqual(self.program.buf, buf)

    def test_send(self):
        self.program.make_buf()
        self.program.send()
        self.msock().sendto.assert_called_with(self.program.buf, ('ntp.pool.org', 123))

    def test_send2(self):
        self.program.make_buf()
        self.program.count = 2
        self.program.send()
        self.msock().sendto.assert_called_with(self.program.buf, ('ntp3.stratum2.ru', 123))

    def test_send3(self):
        self.program.make_buf()
        self.program.count = 5
        self.program.send()
        self.msock().sendto.assert_called_with(self.program.buf, ('ntp1.stratum1.ru', 123))

    def test_parse_sec(self):
        self.program.parse_sec(self.data)
        self.assertEqual(self.program.time_send, 0)

    def test_parse_sec2(self):
        self.program.parse_sec(self.data)
        self.assertEqual(self.program.time_rec, 0)

    def test_parse_sec3(self):
        self.program.parse_sec(self.data)
        self.assertEqual(self.program.time_start, 0)

    def test_parse_msec(self):
        self.program.parse_msec(self.data)
        self.assertEqual(self.program.msec_transmit, 2208988800/10000000)

    def test_parse_msec2(self):
        self.program.parse_msec(self.data)
        self.assertEqual(self.program.msec_rec, 2208988800/10000000)

    def test_parse_msec3(self):
        self.program.parse_msec(self.data)
        self.assertEqual(self.program.msec_start, int(2208988800/10000000))
if __name__ == '__main__':
    unittest.main()

