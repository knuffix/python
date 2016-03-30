from tkinter import messagebox, filedialog
import tkinter as tk
import sys
import threading, re
import chat

SMILEYS=[
    'ball',
    'dknow',
    'flowers',
    'hello',
    'itsok',
    'love',
    'rose',
    'thumbup',
    'wizard'
]


class GUI:
    def __init__(self, program):
        '''
        Creating and filling the window
        :return:
        '''
        self.program = program
        self.type_gui_message = {
            '0': self.add_msg_to_text_box,
            '1': self.add_to_client_list,
            '2': self.refresh_client_list,
            '3': self.add_error_to_text_box,
        }
        self.addr = '127.0.0.1', int(self.program.sock.getsockname()[1])
        #self.addr = self.program.get_lan_ip(), int(self.program.sock.getsockname()[1])
        self.root = tk.Tk()
        self.root.title('Simple chat ver 1.0.1')
        self.root.resizable(width=False, height=False)
        self.root.protocol("WM_DELETE_WINDOW", self.exit_event)
        self.ent = tk.Entry(width=60)
        self.lab = tk.Label(text='Address: ' +
                            self.addr[0] + ' / port: ' + str(self.addr[1]))
        self.txt = tk.Text(width=50, height=15)
        self.txt.config(state='disabled')
        self.but = tk.Button(text='Send', command=lambda: self.button_event())
        self.ent.bind("<Return>", lambda x: self.button_event())
        self.clients = tk.Listbox(height=15)
        self.menu = tk.Menu()
        self.root.config(menu=self.menu)
        self.threads = []
        self.images = {}
        for smile in SMILEYS:
            self.images[smile] = tk.PhotoImage(file='images/'+smile+'.gif')
        self.nick_reciever =''
        self.file = tk.Menu(self.menu, tearoff=0)
        self.file.add_command(label="Connect", command=self.popup_connect_window)
        self.file.add_command(label="Disconnect", command=self.program.disconnect)
        self.file.add_command(label="Send File", command=self.file_dialog)
        self.file.add_command(label="Exit", command=self.exit_event)
        self.menu.add_cascade(label="File", menu=self.file)
        self.clients.pack(side='right')
        self.lab.pack()
        self.txt.pack()
        self.ent.pack(side='left')
        self.but.pack(side='right')
        self.root.after(100, lambda: self.checker())
        self.root.mainloop()

    def file_dialog(self):
        '''
        popup sending file window
        :return:
        '''
        filename = filedialog.askopenfile(mode='rb')
        if filename:
            self.popup_nickname_window()
            if self.nick_reciever != '':
                self.send_file_thread = threading.Thread(target=self.program.send_file,
                                                         args=(filename, self.nick_reciever))
                self.send_file_thread.setDaemon(True)
                self.threads.append(self.send_file_thread)
                self.send_file_thread.start()
            else:
                chat.PIPE.put('3' + 'You did not wrote nickname reciever')

    def popup_connect_window(self):
        '''
        popup connect window
        :return:
        '''
        top = self.top = tk.Toplevel(self.root)
        top.title('Connect')
        l=tk.Label(top,text="IP")
        l.pack()
        l2=tk.Label(top,text="PORT")
        l2.pack()
        self.entry_ip=tk.Entry(top, width = 30)
        self.entry_ip.pack()
        self.entry_port=tk.Entry(top, width = 30)
        self.entry_port.pack()
        b=tk.Button(top,text='Connect',command=self.get_values_from_cw)
        b.pack(side=tk.BOTTOM)

    def popup_nickname_window(self):
        '''
        popup nickname window
        :return:
        '''
        top = self.top = tk.Toplevel(self.root)
        top.title('Write nickname')
        l=tk.Label(top,text="Whom you want to send the file")
        l.pack()
        self.entry_nick=tk.Entry(top)
        self.entry_nick.pack()
        b=tk.Button(top,text='Ok',command=self.get_values_from_nw)
        b.pack()
        self.root.wait_window(self.top)

    def get_values_from_cw(self):
        '''
        Get values from connect window
        :return:
        '''
        ip=self.entry_ip.get()
        port = self.entry_port.get()
        self.top.destroy()
        self.program.connect_to(ip, port)

    def get_values_from_nw(self):
        '''
        Get values from nickname window
        :return:
        '''
        self.nick_reciever = self.entry_nick.get()
        self.top.destroy()

    def add_error_to_text_box(self, msg):
        '''
        Add error message to text box
        :param msg: message
        '''
        self.txt.config(state='normal')
        self.txt.insert(tk.END, 'Error : ' + msg + '\n')
        self.txt.see('end')
        self.txt.config(state='disabled')

    def add_msg_to_text_box(self, msg):
        '''
        Add message to text box
        :param msg: message
        '''

        ind = re.finditer(':[^:]+:', msg)
        for x in ind:
            smiley = msg[x.start()+1:x.end()-1]
            line_number = str(int(self.txt.index('end').split('.')[0])-1)
            message = msg[:x.start()] + msg[x.end():]
            if smiley in SMILEYS:
                self.txt.config(state='normal')
                self.txt.insert(line_number+'.0', self.now_time() + ' ' +
                            message + '\n')
                self.txt.image_create(line_number + '.' + str(x.end()+2),
                                        image=self.images[smiley])
                self.txt.see('end')
                self.txt.config(state='disabled')
                return
            else:
                self.txt.config(state='normal')
                self.txt.insert(tk.END, self.now_time() + ' ' + msg + '\n')
                self.txt.see('end')
                self.txt.config(state='disabled')
                return
        self.txt.config(state='normal')
        self.txt.insert(tk.END, self.now_time() + ' ' + msg + '\n')
        self.txt.see('end')
        self.txt.config(state='disabled')

    def now_time(self):
        """
        Return current time
        :return: time by HH:MM:SS
        """
        from datetime import datetime
        cur_time = datetime.now().time()
        return cur_time.strftime("%H:%M:%S")

    def add_to_client_list(self, nick):
        '''
        Add user to client list
        :param nick: nick
        '''
        self.clients.insert(1, nick)

    def refresh_client_list(self, *kwargs):
        '''
        Refreshing the list of clients
        :param kwargs: must be here, because other GUI messages have arg
        '''
        self.clients.delete(0, tk.END)
        for addr, nick in self.program.connected.items():
            self.clients.insert(1, nick)

    def exit_event(self):
        '''
        Protocol for close button event
        '''
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            for client in self.program.connected.keys():
                self.program.sock.sendto('3'.encode('utf-8'), client)
            self.root.destroy()
            sys.exit(1)

    def button_event(self):
        """
        Runs when you press 'send'
        """
        msg = self.ent.get()
        if len(msg) > 1000:
            chat.PIPE.put('3' + 'Too large message(max 1000)')
            return
        if msg:
            self.txt.config(state='normal')
            self.ent.delete('0', tk.END)
            chat.PIPE.put('0' + 'me--> '+ msg)
            self.program.send_msg(msg)
            self.txt.config(state='disabled')

    def checker(self):
        """
        Refresh gui
        """
        for thread in self.threads:
            if not thread.is_alive():
                thread.join()
        if chat.PIPE:
            if not chat.PIPE.empty():
                event = chat.PIPE.get()
                act_code, act = event[0], event[1:]
                self.type_gui_message[act_code](act)
        self.root.after(100, lambda: self.checker())
