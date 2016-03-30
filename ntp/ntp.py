import socket, struct, select, time, sys
from argparse import ArgumentParser

SERVERS = ['ntp2.stratum2.ru',
         'ntp3.stratum2.ru',
         'ntp4.stratum2.ru',
         'ntp5.stratum2.ru',
         'ntp1.stratum1.ru',
         'ntp2.stratum1.ru',
         'ntp3.stratum1.ru',
         'ntp4.stratum1.ru',
         'ntp5.stratum1.ru',
         'ntp.pool.org'
         ]
PORT = 123
TIME1970 = 2208988800 #Number of seconds from 1st January 1900 to start of Unix epoch
BUFFER_SIZE = 1024


class ntpClient():
    def __init__(self, view, count, timeout):
        self.timeout=timeout
        self.count = count
        self.view = view
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recieved_data = {}

    def make_buf(self):
        shift = 2 << 3
        shift |= 3
        self.buf = struct.pack('!BBBbIIIQQQQ', shift, 0,0,0,0,0,0,0,0,0,0)

    def send(self):
        try:
            self.sec_send = int(time.time())
            self.msec_send = int((time.time()-int(time.time()))*1000)
            for i in range(self.count):
                self.sock.sendto(self.buf, (SERVERS[i], PORT))
        except:
            pass

    def recieve(self):
        for i in range(self.count):
            read, write, exc = select.select([self.sock],[],[],self.timeout)
            if not read:
                print('Timeout recieve to {}'.format(SERVERS[i]))
            for i in read:
                try:
                    data, addr = i.recvfrom(BUFFER_SIZE)
                    if data:
                        self.recieved_data[addr] = data
                except:
                    print('error recieve')

    def parse_sec(self, data):
        ntp_frame = struct.unpack('!12I', data)
        self.time_send = ntp_frame[10] - TIME1970
        self.time_rec = ntp_frame[8] - TIME1970
        self.time_start = self.time_rec

    def parse_msec(self, data):
        ntp_frame = struct.unpack('!12I', data)
        self.psec_client = ntp_frame[11]
        self.msec_transmit = self.psec_client / 10000000
        self.psec_rec = ntp_frame[9]
        self.msec_rec = self.psec_rec / 10000000
        self.msec_start = int(self.msec_rec)

    def calculate_time(self):
        self.sec_delay = (self.sec_send - self.time_start) - (self.time_send - self.time_rec)
        self.msec_delay = int((self.msec_send - self.msec_start) - (self.msec_transmit - self.msec_rec))
        if self.msec_delay < 0 and self.sec_delay > 0:
            self.sec_delay -=1
            self.msec_delay += 1000
        self.sec_offset = (self.time_rec - self.time_start + self.time_send - self.sec_send)/2
        self.msec_offset = (int(self.msec_rec - self.msec_start +
                                self.msec_transmit - self.msec_send)/2)
        if self.msec_offset < 0 and self.sec_offset > 0:
            self.sec_offset -=1
            self.msec_offset += 1000
        self.cur_time_sec = self.sec_send + self.sec_offset
        self.cur_time_msec = int((self.msec_send + self.msec_offset)/10)

    def run(self):
        self.make_buf()
        self.send()
        self.recieve()
        for addr, data in self.recieved_data.items():
            self.parse_sec(data)
            self.parse_msec(data)
            self.calculate_time()
            if not self.view:
                print('*********   RECIEVED FROM {}   **********'.format(addr[0]))
                print('Real time:' + time.ctime(self.cur_time_sec)
                      + ' and ' + str(self.cur_time_msec)+ 'ms')
                print('********************************************************************')
            else:
                print('*********   RECIEVED FROM {}   **********'.format(addr[0]))
                print('Real time:   ' + time.ctime(self.cur_time_sec)
                      + ' and ' + str(self.cur_time_msec) + 'ms')
                ser_time = time.ctime(self.time_start)
                print('Server time: {} and {} ms'.format(ser_time, self.msec_start))
                print('Clock offset: {}s, {}ms'.format(self.sec_offset, self.msec_offset))
                print('Roundtrip delay: {}s, {}ms'.format(self.sec_delay, self.msec_delay))
                print('********************************************************************')

def main():
    parser = ArgumentParser(description='ntp client')
    parser.add_argument('--full', help='See full info', action='store_true')
    parser.add_argument('-c', help='Count of ntp-servers to'+
                                   ' use(default = {}, max = {})'.format(len(SERVERS),len(SERVERS)),
                        type=int, default=len(SERVERS))
    parser.add_argument('-t', help='Timeout to recieve in seconds(default = 5)',
                        type=int, default=5)
    arguments = parser.parse_args()
    if arguments.c > len(SERVERS):
        print('Too much count of ntp-servers. Using default value')
        arguments.c = len(SERVERS)
    if arguments.c < 0:
        print('Invalid count of ntp-servers. Using default value')
        arguments.c = len(SERVERS)
    if arguments.t < 0:
        print('Invalid timeout. Using default value')
        arguments.t = 5
    if arguments.full:
        client = ntpClient(True, arguments.c, arguments.t)
        client.run()
    else:
        client = ntpClient(False, arguments.c, arguments.t)
        client.run()

if __name__ == '__main__':
    main()
