import asyncio
import json
import logging
import math
import os
import socket
import sys
import time
from threading import Thread
from PyQt5 import QtCore, QtGui, QtWidgets
from psutil import cpu_percent
from data import data # data.py
from socket_queue import SocketQueue  # socket_queue.py

__version__ = 2.6
base = 1024
segment = base * 2  # 防止切断
delay = 0.005

new_file = 0
update_file = 1
request_file = 2
normal_text = 3
loop = asyncio.get_event_loop()


class QLogger(logging.Handler):
    def __init__(self, *args, **kwargs):
        logging.Handler.__init__(self, *args, **kwargs)
        self.output = lambda *_: None
        self.setFormatter(logging.Formatter(
            "[<font color='darkgreen'>%(asctime)s</font>(<font color='blue'>%(levelname)s</font>)]:  <font color='brown'>%(message)s</font>"))

    def emit(self, record):
        record = self.format(record)
        if hasattr(self, "output"):
            self.output(record)

    def connect(self, func):
        if callable(func):
            self.output = func


def threading(Daemon, name=None, **kwargs):
    thread = Thread(**kwargs)
    thread.setDaemon(Daemon)
    if name:
        thread.setName(name)
    thread.start()
    return thread


file_thread = threading(True, "文件传输", target=loop.run_forever)


def thread_info(thread: Thread):
    return f"{str(thread._name).ljust(12)}{thread._ident}({thread.__class__.__name__})"


def ignore(function):
    def i(*args, **kwargs):
        try:
            function(*args, **kwargs)
        except:
            return

    return i


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.DEBUG)
Qlog = QLogger()
logger.addHandler(Qlog)
filehandle = logging.FileHandler("log.txt")
filehandle.setFormatter(logging.Formatter("[%(asctime)s(%(levelname)s)]:  %(message)s"))
logger.addHandler(filehandle)
logger.setLevel(logging.DEBUG)


def to_logging(command):
    def logs(*args, **kwargs):
        try:
            _result = command(*args, **kwargs)
            if _result is None:
                return True
            return _result
        except:
            logger.exception(str())
            return False

    return logs


class Command_Handler(object):
    def __init__(self, bind):
        """Bind Client class"""
        assert isinstance(bind, Client)
        self.client = bind

    def _function(self, _list):

        data = {"/info": {"-v": self.get_version(),
                          "-id": self.get_id(),
                          "-i": self.info(),
                          "-h": self.help(),
                          "-name": self.name()},
                }
        _dict = data
        for n in range(len(_list)):
            if type(_dict) == dict:
                _dict = _dict.get(_list[n], self.unknown(" ".join(_list)))
            else:
                break
        if type(_dict) == dict:
            _dict = "Error:\n<font color='blue'>This command must take more arguments. Such as %s.</font>" % list(
                _dict.keys())
        return _dict

    @staticmethod
    def help():
        return """/info [-v] [-id] [-i]
-v : get version of program.
-id : get your id.
-i : get information.
-h : help.
-name : get your name
For example, <font color=red>/info -id</font>"""

    @staticmethod
    def get_version():
        return "version : " + str(__version__)

    def get_id(self):
        return "Your id is {}.".format(id(self.client))

    def name(self):
        return "Your name is {}.".format(self.client.username)

    def info(self):
        return f"Socket Server[version {self.get_version()}] By zmh."

    def unknown(self, s):
        return """Error:
No command named "%s". Please search [/info -h] to help.
%s""" % (s, self.help())

    def cut(self, string):
        return string.strip().split()

    def handler(self, c):
        return "<font color='gray'>[command]</font><font color='brown'>%s</font>\n%s" % (
            c, str(self._function(self.cut(c))))

    def iscommand(self, i):
        return i.strip().startswith("/")


class Server:
    join_message = "<font color='red'>Server></font> <font color='blue'>%s(%s)</font> 连接服务器. 当前在线人数: <font color='red'>%s</font>"
    user_message = "<font color='%s'>%s(%s)%s></font> %s"
    quit_message = "%s(%s) 下线了, %s"

    def __init__(self, usernumUpdate=lambda _: None):
        self.user_num_change = usernumUpdate

    def Setup(self, addr, port, backlog=10, max_count=base ** 2, encode='utf8'):
        self.user_handle = message_handle(self)
        self.address = addr, port
        self.backlog = backlog
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(self.address)
        self.socket.listen(backlog)
        self.max_count = max_count
        self.connect = []
        self.encode = encode
        self.user_record = data()
        return self.run()

    def clear_socket(self, clear_ms=500):
        logger.info(f"Clear the closed socket once every {clear_ms} ms.")
        while True:
            del_list = list(filter(lambda c: hasattr(c, 'Quitted') or (not c.isOpen()), self.connect))
            for user in del_list:
                self.connect.remove(user)
            # if del_list:
            #   logger.info(f"Clear the closed client socket, number is {len(del_list)}.")
            # else:
            #   logger.info('None of the sockets have been cleaned.')
            time.sleep(clear_ms / 1000)

    def run(self):
        logger.debug(f"Server [{':'.join(map(str, self.address))}] on.")
        logger.info(f"Server pid {os.getpid()}.")
        logger.info(f"Max receive length {convert(self.max_count, fine=True)}.")
        logger.info(
            f"Single file transfer speed ≤ <font color='blue'>{convert(segment * (1 // delay // 10))}/s<font>({convert(segment)} × {int(1 // delay)})")
        gui.Database_signal.emit("<font color='gray'>[Transfer speed[-SEGMENT]] = [Maximum load] ÷ 2.</font>")
        logger.info("Backlog number: " + str(self.backlog))
        logger.info('The CODEC is sent as ' + self.encode)
        logger.info("The server is listening on the port.")
        threading(Daemon=True, name="离线清理", target=self.clear_socket)
        return threading(Daemon=True, name="监听端口", target=self.accept_client)

    def _get_Clients(self) -> list:
        def func(c):
            return c.__filter__()

        return list(filter(func, self.connect))

    def _get_sockets(self):  # return int
        i = len(self._get_Clients())
        self.user_num_change(i)
        return i

    def _str_sockets(self):
        return f"当前人数 {self._get_sockets()}"

    def ServerMessage(self, mes, inc=True):
        for user in self._get_Clients():
            if user.__filter__():
                user.send(mes)

    def UserMessage(self, address, _user, mes, inc=True):
        if not mes:
            return
        for user in self.connect:
            if user.__filter__():
                username = user.username
                send_message = Server.user_message % ("brown" if _user == username else "red",
                                                      _user,
                                                      address,
                                                      "(我自己)" if _user == username else "",
                                                      mes)
                user.send(send_message)
        logger.info(f"{address}[{_user}] : {mes}")

    def error_handle(self):
        for user in filter(lambda c: not c.isOpen(), self.connect):
            self.connect.remove(user)

    def accept_client(self):
        while True:
            sock, (address, _) = self.socket.accept()  # 阻塞，等待客户端连接
            self.connect.append(Client(sock, address, self))
            logger.info(f'The address {address} is connected to the server.')

    def quit(self, username, address):
        QuitMessage = Server.quit_message % (username, address, self._str_sockets())
        logger.info(QuitMessage)
        self.ServerMessage(QuitMessage, False)

    def login(self, username, address):
        logger.info(f"{address}[{username}] 登录服务器 , " + self._str_sockets())
        self.ServerMessage(Server.join_message % (username, address, self._get_sockets()))


class Client(SocketQueue):
    def __init__(self, socket, addr, server: Server):
        super(Client, self).__init__(socket, server.max_count, server.encode)
        self.addr = addr
        if not isinstance(server, Server):
            raise ValueError
        self.server = server
        self.username = str()
        self.com = Command_Handler(self)
        self.thread = threading(True, name=f"客户端{self.addr}", target=self.forever_receive)
        self._login = False

    def normal_text(self, s):
        return repr((normal_text, s)).encode(self.codec)

    def isLogin(self) -> bool:
        return getattr(self, "_login", False)

    def __filter__(self) -> bool:
        """返回是否在线并已可接受消息"""
        return self.isLogin() and self.isOpen()

    def json_data(self):
        while self.isOpen():
            try:
                return json.loads(self.recv())
            except TypeError:
                self.quit()

    def quitEvent(self) -> None:
        self.server.quit(self.username, self.addr)

    def parse_argument(self, arg: str) -> str:
        return self.server.user_handle.handle(arg.strip(), self)

    @ignore
    def forever_receive(self):
        while self.isOpen():
            result, reason, uname = self.server.user_record.handler(**self.json_data())
            self.send(json.dumps({"result": result, "reason": reason}))
            if result:
                self.username = uname
                break

        self._login = True
        self.server.login(self.username, self.addr)

        while self.isOpen():
            string = self.recv()
            if string is None:
                continue
            elif self.com.iscommand(string):
                self.send(self.com.handler(string))
            else:
                self.server.UserMessage(self.addr, self.username, string)


def get_host_ip() -> str:
    """get current IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


class Interface(QtWidgets.QMainWindow):
    Database_signal = QtCore.pyqtSignal(str)
    Usernum_signal = QtCore.pyqtSignal(int)

    New_file_signal = QtCore.pyqtSignal(str, int, int, int)
    Update_file_signal = QtCore.pyqtSignal(int)

    def __init__(self):
        super(Interface, self).__init__()
        self.setWindowIcon(QtGui.QIcon("images/server.png"))
        self.setupUi()
        self.show()

    def setupUi(self):
        self.setObjectName("MainWindow")
        self.resize(1088, 685)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(11)
        self.setFont(font)
        self.setStyleSheet("")
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setObjectName("label_6")
        self.gridLayout.addWidget(self.label_6, 4, 0, 1, 1)
        self.textEdit_2 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_2.setObjectName("textEdit_2")
        self.gridLayout.addWidget(self.textEdit_2, 5, 0, 1, 1)
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setObjectName("groupBox")
        self.formLayout_2 = QtWidgets.QFormLayout(self.groupBox)
        self.formLayout_2.setObjectName("formLayout_2")
        self.label_2 = QtWidgets.QLabel(self.groupBox)
        self.label_2.setObjectName("label_2")
        self.formLayout_2.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.label_2)
        self.lineEdit = QtWidgets.QLineEdit(self.groupBox)
        self.lineEdit.setObjectName("lineEdit")
        self.formLayout_2.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.lineEdit)
        self.label_8 = QtWidgets.QLabel(self.groupBox)
        self.label_8.setObjectName("label_8")
        self.formLayout_2.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.label_8)
        self.lineEdit_3 = QtWidgets.QLineEdit(self.groupBox)
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.formLayout_2.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.lineEdit_3)
        self.label_7 = QtWidgets.QLabel(self.groupBox)
        self.label_7.setObjectName("label_7")
        self.formLayout_2.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.label_7)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.groupBox)
        self.lineEdit_2.setReadOnly(True)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.formLayout_2.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.lineEdit_2)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.formLayout_2.setItem(5, QtWidgets.QFormLayout.LabelRole, spacerItem)
        self.pushButton = QtWidgets.QPushButton(self.groupBox)
        self.pushButton.setObjectName("pushButton")
        self.formLayout_2.setWidget(5, QtWidgets.QFormLayout.FieldRole, self.pushButton)
        self.lineEdit_4 = QtWidgets.QLineEdit(self.groupBox)
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.formLayout_2.setWidget(3, QtWidgets.QFormLayout.FieldRole, self.lineEdit_4)
        self.label_9 = QtWidgets.QLabel(self.groupBox)
        self.label_9.setObjectName("label_9")
        self.formLayout_2.setWidget(3, QtWidgets.QFormLayout.LabelRole, self.label_9)
        self.label_10 = QtWidgets.QLabel(self.groupBox)
        self.label_10.setObjectName("label_10")
        self.formLayout_2.setWidget(4, QtWidgets.QFormLayout.LabelRole, self.label_10)
        self.lineEdit_5 = QtWidgets.QLineEdit(self.groupBox)
        self.lineEdit_5.setObjectName("lineEdit_5")
        self.formLayout_2.setWidget(4, QtWidgets.QFormLayout.FieldRole, self.lineEdit_5)
        self.gridLayout.addWidget(self.groupBox, 0, 0, 4, 1)
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.gridLayout.addWidget(self.line, 2, 1, 4, 1)
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("Comic Sans MS")
        font.setPointSize(14)
        font.setBold(False)
        font.setWeight(50)
        self.label_5.setFont(font)
        self.label_5.setStyleSheet(
            "background-color:qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1, stop:0 rgba(0, 255, 241, 255), stop:0.930348 rgba(0, 158, 255, 255));\n"
            "color:rgb(85, 0, 255)")
        self.label_5.setObjectName("label_5")
        self.gridLayout.addWidget(self.label_5, 0, 1, 1, 3)
        self.groupBox_2 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_2.setEnabled(False)
        self.groupBox_2.setObjectName("groupBox_2")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.groupBox_2)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.lcdNumber = QtWidgets.QLCDNumber(self.groupBox_2)
        self.lcdNumber.setObjectName("lcdNumber")
        self.gridLayout_2.addWidget(self.lcdNumber, 1, 1, 1, 1)
        self.line_3 = QtWidgets.QFrame(self.groupBox_2)
        self.line_3.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_3.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_3.setObjectName("line_3")
        self.gridLayout_2.addWidget(self.line_3, 3, 0, 1, 2)
        self.listView_2 = FileListWidget(self.groupBox_2)
        self.listView_2.setObjectName("file_list")
        self.gridLayout_2.addWidget(self.listView_2, 5, 0, 1, 2)
        self.label_4 = QtWidgets.QLabel(self.groupBox_2)
        self.label_4.setObjectName("label_4")
        self.gridLayout_2.addWidget(self.label_4, 4, 0, 1, 1)
        self.label_3 = QtWidgets.QLabel(self.groupBox_2)
        self.label_3.setObjectName("label_3")
        self.gridLayout_2.addWidget(self.label_3, 1, 0, 1, 1)
        self.label = QtWidgets.QLabel(self.groupBox_2)
        self.label.setObjectName("label")
        self.gridLayout_2.addWidget(self.label, 0, 0, 1, 1)
        self.progressBar = QtWidgets.QProgressBar(self.groupBox_2)
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.gridLayout_2.addWidget(self.progressBar, 0, 1, 1, 1)
        self.gridLayout.addWidget(self.groupBox_2, 1, 2, 5, 2)
        self.textEdit_2.setReadOnly(True)
        self.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        self.groupBox_2.setEnabled(False)
        self.retranslateUi()
        self.pushButton.clicked.connect(self.run)
        QtCore.QMetaObject.connectSlotsByName(self)
        self.lcdNumber.display(0)
        self.cpu = cpuThread()
        self.cpu.signal.connect(self.progressUpdate)
        self.Database_signal.connect(self.databaseUpdate)
        self.Usernum_signal.connect(self.usernumUpdate)
        Qlog.connect(self.Database_signal.emit)
        self.New_file_signal.connect(self.listView_2.new_file)
        self.Update_file_signal.connect(self.listView_2.update_file)

    def progressUpdate(self, v):
        self.progressBar.setValue(int(v))

    @to_logging
    def handle(self):
        self.max_recv = int(float(eval(self.lineEdit.text())) * 1024)  # 单位是kb, 换算为字节.
        global segment
        segment = self.max_recv // 2
        self.backlog = int(self.lineEdit_3.text())
        self.addr = self.lineEdit_4.text()
        self.port = int(self.lineEdit_5.text())
        server.Setup(self.addr, self.port, self.backlog, self.max_recv)

    def run(self, _):
        if self.handle():
            self.groupBox.setEnabled(False)
            self.groupBox_2.setEnabled(True)
            self.cpu.start()

    def databaseUpdate(self, data: str):
        if data:
            time.sleep(0.01)  # Qpainter 过快导致死机
            self.textEdit_2.append(data.strip())
        self.textEdit_2.moveCursor(QtGui.QTextCursor.End)

    def usernumUpdate(self, i):
        if i != int(self.lcdNumber.value()):
            self.lcdNumber.display(i)

    def retranslateUi(self, ):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "Socket Server"))
        self.label_6.setText(_translate("MainWindow", "Database(Logging and traceback):"))
        self.groupBox.setTitle(_translate("MainWindow", "Server Setup"))
        self.label_2.setText(_translate("MainWindow", "Maximum load(kb):"))
        self.lineEdit.setText(_translate("MainWindow", "1024"))
        self.label_8.setText(_translate("MainWindow", "backlog:"))
        self.lineEdit_3.setText(_translate("MainWindow", "10"))
        self.label_7.setText(_translate("MainWindow", "CODEC(Unalterable):"))
        self.lineEdit_2.setText(_translate("MainWindow", "utf8"))
        self.pushButton.setText(_translate("MainWindow", "Run"))
        self.lineEdit_4.setText(_translate("MainWindow", "127.0.0.1"))
        self.label_9.setText(_translate("MainWindow", "Address:"))
        self.label_10.setText(_translate("MainWindow", "Port:"))
        self.lineEdit_5.setText(_translate("MainWindow", "429"))
        self.label_5.setText(_translate("MainWindow", f"TCP Server v{__version__}"))
        self.groupBox_2.setTitle(_translate("MainWindow", "Run"))
        self.label_4.setText(_translate("MainWindow", "Receive files:"))
        self.label_3.setText(_translate("MainWindow", "Online user(s):"))
        self.label.setText(_translate("MainWindow", "Running memory with CPU"))


class Item(QtWidgets.QListWidgetItem):
    def __init__(self, *args, **kwargs):
        super(Item, self).__init__(*args, **kwargs)
        self.setSizeHint(QtCore.QSize(200, 80))


class FileArgumentWidget(QtWidgets.QWidget):
    def __init__(self, name, total, itemindex, size, parent=None):
        super(FileArgumentWidget, self).__init__(parent)
        self.size = size
        self.total = total
        self.index = 0
        self.segment = math.ceil(self.size // self.total)

        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        hbox = QtWidgets.QHBoxLayout(self)
        vbox = QtWidgets.QVBoxLayout()
        vbox.addWidget(QtWidgets.QLabel(name + f"\n({convert(self.size)})", self))
        progress = QtWidgets.QProgressBar()
        progress.setMaximum(total)
        progress.setStyleSheet("QProgressBar{\n"
                               "text-align: center;\n"
                               'font: 9pt "Consolas";\n'
                               "}")
        vbox.setObjectName("name, speed Info")
        hbox.setObjectName("Info and Progress")
        progress.setTextVisible(True)
        progress.setRange(0, 0)
        self.label = QtWidgets.QLabel(self)
        self.label.setStyleSheet("color: rgb(60, 112, 255);")
        vbox.addWidget(self.label)
        self.progress = progress
        vbox.setSpacing(2)
        hbox.addLayout(vbox)
        hbox.addWidget(progress)
        self.setLayout(hbox)

        fonts = QtGui.QFont()
        fonts.setFamily("Consolas")
        fonts.setPointSize(9)
        self.setFont(fonts)
        self.label.setFont(fonts)
        self.start_time = time.time()

        item = Item(parent.icon, "", parent)
        item.index_name = itemindex
        parent.addItem(item)
        parent.setItemWidget(item, self)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.timers)
        self.timer.start(50)

    def timers(self, *args) -> None:
        timeit = self.get_time()
        if timeit == 0:
            return  # ZeroDivisionError: integer division or modulo by zero
        contect = f"{convert(int((self.segment * self.index) / timeit))}/s ({self.str_time()} 秒)"
        self.label.setText(contect)

    def get_progress(self) -> QtWidgets.QProgressBar:
        return self.progress

    def is_finished(self) -> bool:
        return bool(self.index >= self.total)

    def update(self) -> None:
        if self.index == 0:
            self.progress.setMaximum(self.total)
        if self.is_finished():
            return
        self.index += 1
        if self.is_finished():
            self.end_time = time.time()
        self.progress.setValue(self.index)

    def get_total(self) -> int:
        return self.total

    def get_time(self) -> float:
        return getattr(self, "end_time", time.time()) - self.start_time

    def str_time(self) -> str:
        return "%0.1f" % (self.get_time())

    def get_index(self) -> int:
        return self.index

    def customContextMenuRequested(self, pos: QtCore.QPoint) -> None:
        pass


class FileListWidget(QtWidgets.QListWidget):
    def __init__(self, parent=None):
        super(FileListWidget, self).__init__(parent)
        self.icon = QtGui.QIcon("images/file.png")
        self.files = {}

    def new_file(self, name, size, index, FILESIZE):
        widget = FileArgumentWidget(name, size, index, FILESIZE, self)
        self.files[index] = widget

    def update_file(self, index) -> None:
        self.files[index].update()


class cpuThread(QtCore.QThread):
    signal = QtCore.pyqtSignal(int)

    def run(self) -> None:
        while True:
            self.signal.emit(int(cpu_percent(interval=1)))


def save_bytes(file, byte: bytes):
    with open(file, "wb") as f:
        f.write(byte)


def get_eval(str, defined=None):
    try:
        res = eval(str)
        if isinstance(res, type(defined)):
            return res
        raise TypeError
    except:
        return defined


class SEND:
    def __init__(self, index, name, conn: callable, encode='utf8', localfile=""):
        self.localfile = localfile
        self.encode = encode
        self.size = os.path.getsize(self.localfile)
        self.total = math.ceil(self.size / segment)
        self.index = index
        self.conn = conn
        self.finish = False
        self.name = name
        asyncio.run_coroutine_threadsafe(self.update(), loop)

    async def update(self):
        self.conn(self.header().encode(self.encode))
        with open(self.localfile, "rb") as f:
            for n in range(self.total):
                self.conn(self.format(n, f.read(segment)).encode(self.encode))
                await asyncio.sleep(delay)
        self.finish = True

    def cut(self, byte: bytes, seg=segment) -> list:
        return [byte[x:x + seg] for x in range(0, len(byte), seg)]

    def format(self, process, data) -> str:
        return repr((update_file, (self.index, process, data)))

    def header(self) -> str:
        return repr((new_file, (self.index,
                                self.name,
                                self.total,
                                self.size)
                     ))


class RECV:
    def __init__(self, index: int, name: str, total: int, size: int):
        self.index, self.name, self.total, self.size = index, name, total, size
        self.progress = -1
        self.file = []
        self.finish = False
        self.save_path = os.path.join(save_path, self.name)
        gui.New_file_signal.emit(name, total, index, size)

    def update(self, p, data):
        if isinstance(p, int) and p - 1 == self.progress:
            self.progress = p
            self.file.append(data)
            gui.Update_file_signal.emit(self.index)
            self.update_file()
            if len(self.file) == self.total:
                logger.info(f"Save {self.name} at {self.save_path}, size {self.size} b.")
                self.finish = True
                return True

    def update_file(self):
        with open(self.save_path, "ab") as f:
            f.write(self.file[-1])

    def save(self):
        return self.finish

    def savepath(self) -> str:
        if self.finish:
            return self.save_path
        return ""


class send_files:
    def __init__(self, encode='utf8'):
        self.sends = []
        self.encode = encode

    def localfile(self, file, conn):
        if os.path.isfile(file):
            _, name = os.path.split(file)
            self.sends.append(
                SEND(len(self.sends), name, conn, localfile=file))  # index: len(self.sends)-1+1  => len(self.sends)


class recv_files:
    def __init__(self, decode='utf8', path=None):
        self.recvs = []
        self.decode = decode
        if path is None:
            path = sys.path[0]
        self.path = path

    def new_files(self, index, name, total, size):
        self.recvs.append(RECV(index, name, total, size))
        logger.info(f"New file - {name} - {convert(size, fine=True)}.")

    def apply(self, index, progress, data):
        if len(self.recvs) - 1 >= index:
            if self.recvs[index].update(progress, data):
                if self.save(index):
                    return index, self.recvs[index].name
                else:
                    return False

    def save(self, index):
        if len(self.recvs) - 1 >= index:
            return self.recvs[index].save()


class message_handle:
    codec = "utf8"

    def __init__(self, server: Server):
        if not os.path.isdir(save_path):
            os.makedirs(save_path)
        self.Sender = send_files(self.codec, )
        self.Receiver = recv_files(self.codec, save_path)
        self.files_record = {}
        self.server = server

    @to_logging
    def handle(self, data, client: Client):
        _res = get_eval(data, tuple())
        if len(_res) == 2:
            type, arguments = _res
            if type == new_file and client.isLogin():
                index, name, total, size = arguments
                if not client.username in self.files_record:
                    self.files_record[client.username] = [len(self.Receiver.recvs), ]
                else:
                    self.files_record[client.username].append(len(self.Receiver.recvs))

                self.Receiver.new_files(len(self.Receiver.recvs), name, total, size)
            elif type == update_file and client.isLogin():
                index, progress, data = arguments
                if client.username in self.files_record:
                    if not len(self.files_record[client.username]) >= index + 1:
                        index = len(self.files_record[client.username]) - 1
                    _res = self.Receiver.apply(self.files_record[client.username][index], progress, data)
                    if _res:
                        INDEX, NAME = _res
                        self.server.UserMessage(client.addr, client.username, f'<a href="{INDEX}">{NAME}</a>')
            elif type == request_file and client.isLogin():
                path = self.Receiver.recvs[arguments].savepath()
                logger.info(f"Client {client.username} requested file {path} ({self.Receiver.recvs[arguments]})")
                if path:
                    self.Sender.localfile(path, client.send)  # 如若无, 报错False
            elif type == normal_text:
                return arguments

    def send(self, sendpath, conn):
        return self.Sender.localfile(sendpath, conn)

    def get_index(self, index):
        if index + 1 <= len(self.Receiver.recvs):
            return self.Receiver.recvs[index]


def convert(byte, fine=False):
    """
    位 bit (比特)(Binary Digits)：存放一位二进制数，即 0 或 1，最小的存储单位。
    字节 byte：8个二进制位为一个字节(B)，最常用的单位。
    其中1024=2^10 ( 2 的10次方)，
    1KB (Kilobyte 千字节)=1024B，
    1MB (Megabyte 兆字节 简称“兆”)=1024KB，
    1GB (Gigabyte 吉字节 又称“千兆”)=1024MB，
    1TB (Trillionbyte 万亿字节 太字节)=1024GB，
    1PB（Petabyte 千万亿字节 拍字节）=1024TB，
    1EB（Exabyte 百亿亿字节 艾字节）=1024PB，
    1ZB (Zettabyte 十万亿亿字节 泽字节)= 1024 EB,
    1YB (Jottabyte 一亿亿亿字节 尧字节)= 1024 ZB,
    1BB (Brontobyte 一千亿亿亿字节)= 1024 YB.
    「山木兮」"""
    if not isinstance(byte, (int, float)):
        byte = len(byte)
    DEI = f"{byte} bytes"
    base = 1024
    units = ["b",
             "Kb",
             "Mb",
             "Gb",
             "Tb",
             "Pb",
             "Eb"]
    index = 0
    while True:
        if byte < 1024 or index + 1 >= len(units):
            break
        byte /= base
        index += 1

    if index == 0:
        return DEI
    else:
        if fine:
            return "%0.1f%s(%s)" % (byte, units[index], DEI)
        else:
            return "%0.1f%s" % (byte, units[index])


if __name__ == "__main__":
    save_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "resource")
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("fusion")
    gui = Interface()
    server = Server(gui.Usernum_signal.emit)
    sys.exit(app.exec_())
