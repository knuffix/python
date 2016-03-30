"""Simple chat application"""
import socket
import threading, re, select, time, os
from enum import Enum
from queue import Queue

PIPE = Queue()
BUFFER_SIZE = 1024
TIME_TO_DIE = 2.0
RECIEVE_PORT = 12345
MAX_FILE_SIZE = 1024*1024*100


class Method(Enum):
    simple_message = 0
    add_to_network = 1
    add_new_client = 2
    delete_client = 3
    system_message = 4
    change_status = 5
    recieved_pm = 6
    update_clients_event = 7
    recieve_filename = 8
    update_clients_ans = 9


class Program():
    def __init__(self, server, port, nick):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.threads = []
        self.sock.bind(('', 0))
        self.updater = {}
        self.connected = {}
        self.muted = False
        self.nick = nick
        self.addr = '127.0.0.1', int(self.sock.getsockname()[1])
        #self.addr = self.get_lan_ip(), int(self.sock.getsockname()[1])
        self.type_inc_message = {
            '0': self.simple_message,
            '1': self.add_to_network,
            '2': self.add_new_client,
            '3': self.delete_client,
            '4': self.system_message,
            '5': self.change_status,
            '6': self.recieved_pm,
            '7': self.update_clients_event,
            '8': self.recieve_filename,
            '9': self.update_clients_ans
        }
        self.command_catcher = {
            'connect': self.connect_to,
            'disconnect': self.disconnect,
            'kick': self.kick_client,
            'mute': self.mute_client,
            'unmute': self.unmute_client,
            'pm': self.send_pm
        }
        if server and port:
            self.connect_to(server, port)

    def run(self):
        self.thread = threading.Thread(
            target=self.recieving_data, args=(self.sock, self.type_inc_message))
        self.thread.setDaemon(True)
        self.thread.start()
        self.thread_updater = threading.Thread(
            target=self.updater_clients)
        self.thread_updater.setDaemon(True)
        self.thread_updater.start()

    def get_lan_ip(self):
        """
        Return your lan ip
        :return: ipv4
        """
        sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with sck as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]

    def kick_client(self, kicked_nick):
        '''
        Kicking user
        :param kicked_nick: user nick who should be deleted
        '''
        if kicked_nick in self.connected.values():
            for addr, nick in self.connected.items():
                if nick == kicked_nick:
                    self.sock.sendto('5kick'.encode('utf-8'), addr)
                    PIPE.put(
                        str(Method.simple_message.value) +
                        'SYSTEM: You kicked {}'.format(kicked_nick))
                    self.sock.sendto((str(Method.system_message.value) +
                                     ' You\'re kicked').encode('utf-8'), addr)
                else:
                    self.sock.sendto(str(Method.system_message.value) +
                                     '{} was kicked '.format(kicked_nick).encode('utf-8'),
                                     addr)
        elif kicked_nick == self.nick:
            PIPE.put(str(Method.delete_client.value) + 'you can\'t kick yourself')
        else:
            PIPE.put(
                str(Method.delete_client.value) +
                'there is no user with nick {}'.format(kicked_nick))

    def mute_client(self, muted_nick):
        '''
        Muting user (this user can't send messages)
        he can muting himself, but can't unmute
        :param muted_nick: user nick who should be muted
        '''
        if muted_nick in self.connected.values():
            for addr, nick in self.connected.items():
                if nick == muted_nick:
                    self.sock.sendto((str(Method.change_status.value) + 'mute').encode('utf-8'), addr)
                    PIPE.put(
                        str(Method.simple_message.value) +
                        'You muted {}'.format(muted_nick))
                    self.sock.sendto((str(Method.system_message.value) +
                                     ' You\'re muted').encode('utf-8'), addr)
                else:
                    self.sock.sendto((Method.system_message.value +
                                      '{} was muted '.format(
                        muted_nick)).encode('utf-8'), addr)
        elif muted_nick == self.nick:
            self.muted = True
            PIPE.put(str(Method.system_message.value) +
                        ' You are muted yourself')
            for addr, nick in self.connected.items():
                self.sock.sendto((str(Method.system_message.value) +
                                 '{} was muted '.format(
                    muted_nick)).encode('utf-8'), addr)
        else:
            PIPE.put(
                str(Method.delete_client.value) +
                'there is no user with nick {}'.format(muted_nick))

    def recieved_pm(self, msg, pm_addr):
        '''
        Adding private message (pm)
        :param msg: private message
        :param pm_addr: user who sent you pm
        '''
        for addr, nick in self.connected.items():
            if addr == pm_addr:
                PIPE.put(
                    str(Method.simple_message.value) +
                    '{} send you a private message: \n'.format(nick) + msg)

    def change_status(self, msg, addr):
        '''
        Changing status of user
        :param msg: type of status
        :param addr: user who changed status
        '''
        if msg == 'kick':
            self.disconnect()
        if msg == 'mute':
            self.muted = True
        if msg == 'unmute':
            self.muted = False

    def unmute_client(self, unmuted_nick):
        '''
        Unmute user
        :param unmuted_nick: user nick who should be unmuted
        '''
        if unmuted_nick == self.nick:
            PIPE.put(str(Method.delete_client.value) + 'You can\'t unmute yourself')
            return
        if unmuted_nick in self.connected.values():
            for addr, nick in self.connected.items():
                if nick == unmuted_nick:
                    self.sock.sendto((str(Method.change_status.value) +
                                     'unmute').encode('utf-8'), addr)
                    PIPE.put(str(Method.simple_message.value) +
                                'SYSTEM: You unmuted {}'.format(unmuted_nick))
                    self.sock.sendto((str(Method.system_message.value) +
                                     ' You\'re unmuted').encode('utf-8'), addr)
                else:
                    self.sock.sendto((str(Method.system_message.value)+
                                     '{} was unmuted '.format(
                        unmuted_nick)).encode('utf-8'), addr)
        else:
            PIPE.put(
                str(Method.delete_client.value)
                + 'there is no user with nick: {}'.format(unmuted_nick))

    def send_pm(self, pm_nick, msg):
        '''
        Sending a private message
        :param pm_nick: user nick who will recieve pm
        :param msg: message
        '''
        if pm_nick == self.nick:
            PIPE.put(str(Method.simple_message.value) + 'You send yourself a private message: \n' + msg)
            return
        if pm_nick in self.connected.values():
            for addr, nick in self.connected.items():
                if nick == pm_nick:
                    self.sock.sendto((str(Method.recieved_pm.value) + msg).encode('utf-8'), addr)
        else:
            PIPE.put(str(Method.delete_client.value) +
                        'There is no user with nick: {}'.format(pm_nick))

    def system_message(self, event, addr):
        '''
        Add SYSTEM message to textbox
        :param args: event, addr of user who called the event
        '''
        if addr in self.connected.keys():
            PIPE.put(
                str(Method.simple_message.value) +
                'SYSTEM: {} by {}'.format(event, self.connected[addr]))

    def connect_to(self, ip, port):
        '''
        Connecting to network
        :param ip: network ip
        :param port: network port
        '''
        try:
            port = int(port)
        except ValueError:
            PIPE.put(str(Method.delete_client.value) + 'enter the valid port')
            return
        if not (ip, port) in self.connected.keys():
            if int(port) != self.addr[1]:
                PIPE.put(str(Method.simple_message.value) +
                            'SYSTEM: trying connect to {}:{}'.format(ip,port))
                self.sock.sendto((str(Method.add_to_network.value)
                                  + self.nick).encode('utf-8'),
                    (str(ip), int(port)))
            else:
                PIPE.put(str(Method.delete_client.value) +
                            'You can not connect to yourself')
        else:
            PIPE.put(str(Method.delete_client.value) +
                        'You have already connected to this network')

    def simple_message(self, msg, addr):
        '''
        Creating simple message
        :param msg: message
        :param addr: sender
        '''
        if addr in self.connected.keys():
            if msg:
                msg = str(Method.simple_message.value) + self.connected[addr] + '--> ' + msg
                PIPE.put(msg)

    def disconnect(self, *kwargs):
        '''
        Disconnect from network
        :param kwargs: must be here, because other GUI messages have arg
        '''
        if self.connected:
            for client in self.connected.keys():
                self.sock.sendto(str(Method.delete_client.value).encode('utf-8'), client)
            self.connected.clear()
            PIPE.put(str(Method.add_new_client.value) + '')
            PIPE.put(str(Method.simple_message.value)
                        + 'You are disconnected')
        else:
            PIPE.put(str(Method.delete_client.value)
                        + 'You are not connected')

    def add_to_network(self, nick, addr):
        '''
        Adding user to network
         :param nick: nickname of new user
         :param addr: address of new user
        '''
        if addr not in self.connected.keys():
            for client in self.connected.keys():
                to_send = str(Method.add_new_client.value) +\
                          nick + ' ' + addr[0] + ' ' + str(addr[1])
                self.sock.sendto(to_send.encode('utf-8'), client)
            self.connected[addr] = nick
            self.updater[addr] = time.time()
            PIPE.put(str(Method.add_to_network.value) + nick)
            PIPE.put(str(Method.simple_message.value) +
                        '{} was connected'.format(self.connected[addr]))
            to_send = str(Method.add_new_client.value) + self.nick + ' ' + \
                self.addr[0] + ' ' + str(self.addr[1])
            self.sock.sendto(to_send.encode('utf-8'), addr)

    def add_new_client(self, msg, addr):
        '''
        Adding new user recieved by known user
        :param msg: nickname and address of new user
        :param addr: address known user
        '''
        addr_new = re.search(r'(.+?)\s(.+?)\s(.+)', msg)
        addr = (addr_new.group(2), int(addr_new.group(3)))
        if addr not in self.connected.keys():
            to_send = str(Method.add_new_client.value) + self.nick + ' ' + \
                self.addr[0] + ' ' + str(self.addr[1])
            self.sock.sendto(to_send.encode('utf-8'), addr)
            PIPE.put(str(Method.add_to_network.value) + addr_new.group(1))
            self.connected[addr] = addr_new.group(1)
            self.updater[addr] = time.time()
            PIPE.put(str(Method.simple_message.value)
                        + '{} was connected'.format(self.connected[addr]))

    def delete_client(self, msg, addr):
        '''
        Deleting user from dict of connected
        :param msg:
        :param addr: address user who should deleted
        '''
        if addr in self.connected.keys():
            deleted_client_nick = self.connected.pop(addr)
            PIPE.put(str(Method.add_new_client.value))
            PIPE.put(str(Method.simple_message.value) + deleted_client_nick + ' has left')

    def send_file(self, file, nick_reciever):
        if nick_reciever:
            if nick_reciever in self.connected.values():
                for addr, nick in self.connected.items():
                    if nick_reciever == nick:
                        if os.path.getsize(file.name) < MAX_FILE_SIZE:
                            file_name = file.name.split('/')
                            file_name = file_name[len(file_name)-1]
                            self.sock.sendto((str(Method.recieve_filename.value)
                                              +'{}'.format(file_name)).encode('utf-8'), addr)
                            time.sleep(1)
                            tmp_socket = socket.socket()
                            tmp_socket.connect((addr[0], RECIEVE_PORT))
                            tmp_data = file.read(BUFFER_SIZE)
                            PIPE.put(str(Method.simple_message.value) +
                                        ' SYSTEM: sending file {} to {}'.format(file_name,
                                                                         nick_reciever))
                            while tmp_data:
                                tmp_socket.send(tmp_data)
                                tmp_data = file.read(BUFFER_SIZE)
                            file.close()
                            tmp_socket.shutdown(socket.SHUT_WR)
                            #self.sock.sendto(('7{}'.format(file_name)).encode('utf-8'), addr)
                            # data = file.read(BUFFER_SIZE)
                            # while data:
                            #     self.sock.sendto(data, addr)
                            #     time.sleep(0.2)
                            #     data = file.read(BUFFER_SIZE)
                            #self.sock.sendto('9end'.encode('utf-8'),addr)
                            PIPE.put(str(Method.simple_message.value) + 'SYSTEM: file sent')
                        else:
                            PIPE.put(str(Method.delete_client.value)
                            + 'Too large file. Max file size = 100mb')
            else:
                PIPE.put(str(Method.delete_client.value)
                            + 'There\'s no user with nick {}'.format(nick_reciever))
        else:
            PIPE.put(str(Method.delete_client.value)
                        + 'You did not wrote nickname reciever')

    def recieve_filedata_run(self, addr):
        self.thread_recieve_file = threading.Thread(target=self.recieve_filedata, args=addr)
        self.thread_recieve_file.setDaemon(True)
        self.threads.append(self.thread_recieve_file)
        self.thread_recieve_file.start()

    def recieve_filedata(self, addr, data):
        tmp_socket = socket.socket()
        tmp_socket.bind((self.addr[0], RECIEVE_PORT))
        tmp_socket.listen(1)
        c, s_addr = tmp_socket.accept()
        data = c.recv(BUFFER_SIZE)
        while data:
            self.file.write(data)
            data = c.recv(BUFFER_SIZE)
        self.file.close()
        PIPE.put(str(Method.simple_message.value) + 'SYSTEM: FILE RECIEVED')
        tmp_socket.close()

    def recieve_filename(self, data, addr):
        if addr in self.connected.keys():
            self.recieving_filename = data
            PIPE.put(str(Method.simple_message.value) + 'SYSTEM: RECEIEVING FILE {}'.format(self.recieving_filename))
            self.file = open(self.recieving_filename, 'wb')
            self.recieve_filedata_run(addr)
        else:
            pass

    def send_msg(self, msg):
        """
        Send message to all client in dict of connected
        and catching the commands
        :param msg: message to send
        """
        if msg:
            if msg[0] != '/':
                if not self.muted:
                    to_send = (str(Method.simple_message.value) + msg).encode('utf-8')
                    for client in self.connected.keys():
                        self.sock.sendto(to_send, client)
                else:
                    PIPE.put(str(Method.delete_client.value) + 'You are muted')
            else:
                msg = msg[1:]
                try:
                    msg = msg.split(maxsplit=1)
                    if len(msg) > 1:
                        args = msg[1].split()
                        self.command_catcher[msg[0]](*args)
                    else:
                        self.command_catcher[msg[0]]()
                except KeyError as keye:
                    PIPE.put(str(Method.delete_client.value)
                                + 'command {} not found'.format(keye))
                except TypeError as typee:
                    PIPE.put(str(Method.delete_client.value) +
                        ' invalid args')

    def update_clients_req(self):
        for addr, nick in self.connected.items():
            self.sock.sendto(str(Method.update_clients_ans.value).encode('utf-8'), addr)
            self.updater[addr] = 0

    def update_clients_event(self, data, addr):
        if addr in self.connected.keys():
            self.updater[addr] = time.time()

    def update_clients_ans(self, data, addr):
        if addr in self.connected.keys():
            self.sock.sendto(str(Method.update_clients_event.value).encode('utf-8'), addr)

    def delete_died_clients(self):
        for addr in self.updater.keys():
            if time.time() - self.updater[addr] > 2*TIME_TO_DIE:
                self.delete_client('', addr)

    def updater_clients(self):
        while True:
            self.update_clients_req()
            time.sleep(TIME_TO_DIE)
            self.delete_died_clients()



    def recieving_data(self, sock, type_parser):
        """
        Wait messages and connect unknown address
        :param sock: socket
        :param type_parser: dict of message types
        """
        while True:
            read, write, errors = select.select([sock], [], [])
            for i in read:
                try:
                    data, addr = i.recvfrom(BUFFER_SIZE)
                    if data:
                        try:
                            enc_data = data.decode('utf-8')
                            msg_code, msg = enc_data[0], enc_data[1:]
                            type_parser[msg_code](msg, addr)
                        except:
                            pass
                except ConnectionResetError:
                    pass




