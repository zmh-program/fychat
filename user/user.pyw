# -*- coding: utf-8 -*-
# Form implementation generated from reading ui files 'USER.ui', 'Connect.ui'
# Created by: PyQt5 UI code generator 5.15.4
# writer : Zmh

import asyncio
import json
import logging
import math
import os
import socket
import sys
import time
from datetime import datetime
from threading import Thread
from time import sleep
from traceback import format_exc
from PyQt5 import QtCore, QtGui, QtWidgets, QtWebEngineWidgets
from PyQt5.QtCore import QPropertyAnimation

from socket_queue import SocketClient

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s")
TIMEOUT = 2

base = 1024
bufsize = base ** 2
segment = bufsize // 2  # 防止切断
delay = 0.01

new_file = 0
update_file = 1
request_file = 2
normal_text = 3

ip_list = ["localhost:429",
           "103.46.128.21:51203",
           "127.0.0.1:429",
           "EXAM-41:429"]

loop = asyncio.get_event_loop()
file_thread = Thread(target=loop.run_forever)


def get_host_ip() -> str:
    """get current IP address"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(('8.8.8.8', 80))
        ip = sock.getsockname()[0]
    finally:
        sock.close()
    return ip


Username = str()


def threading(Daemon, **kwargs):
    thread = Thread(**kwargs)
    thread.setDaemon(Daemon)
    thread.start()
    return thread


def to_logging(command):
    def logs(*args, **kwargs):
        try:
            _result = command(*args, **kwargs)
            if _result is None:
                return True
            return _result
        except socket.timeout:
            return
        except (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError):
            if "main" in globals():
                main.ConnectionError_signal.emit()
            return "CLOSE"
        except:
            if "main" in globals():
                main.MessageUpdate_signal.emit(format_exc())
            else:
                logging.exception(str())
            return False

    return logs


class Socket(SocketClient):
    def __init__(self, Function=lambda i: None, code='utf-8'):
        super(Socket, self).__init__(codec=code)
        self.handler = message_handle(self.send)
        self.__old_addr = ()

    def parse_argument(self, arg: str) -> str:
        return self.handler.handle(arg.strip())

    def receive_text(self):
        return super(Socket, self).recv()

    def recv(self):
        result = super(Socket, self).recv()
        if isinstance(result, str) and result:
            self._traceback(f'{result}                  <font size=1>{convert(len(result))}</font>')
        return self.isOpen()

    def forever_receive(self) -> None:
        self.handler.send_text(self.header)
        while True:
            if not self.recv():
                return

    def Check_info(self, *args, **kwargs):
        threading(True, target=lambda: self.__Check_info(*args, **kwargs))

    def __Check_info(self, info, emit, return_func, err_func):
        if not self.is_connect() and self.__old_addr != self.addr:
            res, trace = self.connect()
            emit(bool(res))
            if not res:
                return err_func(trace)
        else:
            emit(True)
        self.handler.send_text(json.dumps(info))
        emit(True)
        data = self.receive_text()
        emit(True)
        try:
            data = json.loads(data)
        except (ValueError, KeyError):
            return err_func("解析异常!")
        else:
            emit(True)
            return_func(data)

    def run(self):  # 线程
        threading(True, target=self.forever_receive)

    def quitEvent(self):
        self.__is_connect = False
        if main.is_setup:
            main.ConnectionError_signal.emit()


LOGIN_INFO_FILE = "config.json"
LOGIN_INFO = {"type": 0,
              "username": "",
              "password": ""}

if os.path.isfile(LOGIN_INFO_FILE):
    with open(LOGIN_INFO_FILE, "r") as f:
        LOGIN_INFO = json.load(f)


def json_dump():
    with open(LOGIN_INFO_FILE, "w") as f:
        json.dump(LOGIN_INFO, f, indent=4)


def Animation(parent, type=b"windowOpacity", from_value=0, to_value=1, ms=1000, connect=None):
    anim = QPropertyAnimation(parent, type)
    anim.setDuration(ms)
    anim.setStartValue(from_value)
    anim.setEndValue(to_value)
    if connect:
        anim.finished.connect(connect)
    anim.start()
    return anim


class LoadingProgress(QtWidgets.QDialog):
    update_signal = QtCore.pyqtSignal(bool)

    def __init__(self, parent=None):
        super(LoadingProgress, self).__init__(parent)
        self.value = 0
        self.update_signal.connect(self.update_progress)
        vbox = QtWidgets.QVBoxLayout(self)
        self.steps = [f"连接服务器中({TIMEOUT}s)...",
                      "发送数据中...",
                      "接收数据中...",
                      "解析数据中..."]
        self.movie_label = QtWidgets.QLabel()
        self.movie = QtGui.QMovie("images/loading.gif")
        self.movie_label.setMovie(self.movie)
        self.movie.start()
        self.progress_label = QtWidgets.QLabel()
        self.label_update()

        vbox.addWidget(self.movie_label)
        vbox.addWidget(self.progress_label)
        self.setLayout(vbox)
        # self.exec_()

    def label_update(self):
        self.progress_label.setText(self.steps[self.value])

    def update_progress(self, boolean: bool) -> None:
        self.value += 1
        if boolean and self.value < len(self.steps):
            self.label_update()
        else:
            self.close()


class User_Setup(QtWidgets.QDialog):
    end_anim, start_anim = None, None
    log_progress_signal = QtCore.pyqtSignal(str)
    reg_progress_signal = QtCore.pyqtSignal(str)
    handle_signal = QtCore.pyqtSignal(dict)
    err_signal = QtCore.pyqtSignal(str)
    loading_dialog = None
    successful = False

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if not self.end_anim:
            self.end_anim = Animation(self, ms=2000, from_value=1, to_value=0, connect=self.close)
            event.ignore()
        else:
            if self.successful:
                main.SetupUi()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.start_anim = Animation(self, ms=2000)
        palette = QtGui.QPalette()
        palette.setBrush(self.backgroundRole(),
                         QtGui.QBrush(QtGui.QPixmap('images/interface_background.jpg')))  # 设置背景图片
        self.setPalette(palette)

        self.setObjectName("Dialog")
        self.resize(362, 394)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(12)
        self.setFont(font)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("images/user.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.setWindowIcon(icon)
        self.setAutoFillBackground(True)
        self.gridLayout = QtWidgets.QGridLayout(self)
        self.gridLayout.setObjectName("gridLayout")
        self.label = QtWidgets.QLabel(self)
        self.label.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.label.setStyleSheet("")
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap("images/zmh.png"))
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.tabWidget = QtWidgets.QTabWidget(self)
        self.tabWidget.setAccessibleName("")
        self.tabWidget.setObjectName("tabWidget")
        self.log = QtWidgets.QWidget()
        self.log.setObjectName("login")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.log)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.lineEdit_5 = QtWidgets.QLineEdit(self.log)
        self.lineEdit_5.setStyleSheet("            QLineEdit\n"
                                      "            {border:0px;\n"
                                      "            border-radius:0;\n"
                                      "            font: 12pt \"Consolas\";\n"
                                      "            margin:15px;\n"
                                      "            border-bottom: 2px solid #B3B3B3;}\n"
                                      "            QLineEdit:hover{\n"
                                      "                border-bottom:3px solid #66A3FF;\n"
                                      "            }\n"
                                      "            QLineEdit:focus{\n"
                                      "                border-bottom:3px solid #E680BD\n"
                                      "            }")
        self.lineEdit_5.setText("")
        self.lineEdit_5.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_5.setClearButtonEnabled(True)
        self.lineEdit_5.setObjectName("lineEdit_5")
        self.gridLayout_2.addWidget(self.lineEdit_5, 2, 0, 1, 2)
        self.lineEdit_4 = QtWidgets.QLineEdit(self.log)
        self.lineEdit_4.setStyleSheet("            QLineEdit\n"
                                      "            {border:0px;\n"
                                      "            border-radius:0;\n"
                                      "            font: 12pt \"Consolas\";\n"
                                      "            margin:15px;\n"
                                      "            border-bottom: 2px solid #B3B3B3;}\n"
                                      "            QLineEdit:hover{\n"
                                      "                border-bottom:3px solid #66A3FF;\n"
                                      "            }\n"
                                      "            QLineEdit:focus{\n"
                                      "                border-bottom:3px solid #E680BD\n"
                                      "            }")
        self.lineEdit_4.setClearButtonEnabled(True)
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.gridLayout_2.addWidget(self.lineEdit_4, 1, 0, 1, 2)
        self.pushButton_2 = QtWidgets.QPushButton(self.log)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("images/login.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton_2.setIcon(icon1)
        self.pushButton_2.setObjectName("pushButton_2")
        self.gridLayout_2.addWidget(self.pushButton_2, 6, 1, 1, 1)
        self.checkBox_2 = QtWidgets.QCheckBox(self.log)
        self.checkBox_2.setChecked(True)
        self.checkBox_2.setObjectName("checkBox_2")
        self.gridLayout_2.addWidget(self.checkBox_2, 6, 0, 1, 1)
        self.label_3 = QtWidgets.QLabel(self.log)
        font = QtGui.QFont()
        font.setFamily("Comic Sans MS")
        font.setPointSize(11)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.label_3.setFont(font)
        self.label_3.setStyleSheet("color: rgb(255, 1, 39);\n"
                                   "font: 11pt \"宋体\";")
        self.label_3.setObjectName("label_3")
        self.gridLayout_2.addWidget(self.label_3, 4, 0, 1, 2)
        self.commandLinkButton = QtWidgets.QCommandLinkButton(self.log)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(12)
        self.commandLinkButton.setFont(font)
        self.commandLinkButton.setObjectName("commandLinkButton")
        self.gridLayout_2.addWidget(self.commandLinkButton, 3, 0, 1, 2)
        self.tabWidget.addTab(self.log, "")
        self.reg = QtWidgets.QWidget()
        self.reg.setObjectName("reg")
        self.gridLayout_3 = QtWidgets.QGridLayout(self.reg)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.pushButton = QtWidgets.QPushButton(self.reg)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("images/register.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton.setIcon(icon2)
        self.pushButton.setObjectName("pushButton")
        self.gridLayout_3.addWidget(self.pushButton, 5, 1, 1, 1)
        self.checkBox = QtWidgets.QCheckBox(self.reg)
        self.checkBox.setChecked(True)
        self.checkBox.setTristate(False)
        self.checkBox.setObjectName("checkBox")
        self.gridLayout_3.addWidget(self.checkBox, 5, 0, 1, 1)
        self.lineEdit_3 = QtWidgets.QLineEdit(self.reg)
        self.lineEdit_3.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.lineEdit_3.setAccessibleName("")
        self.lineEdit_3.setStyleSheet("            QLineEdit\n"
                                      "            {border:0px;\n"
                                      "            border-radius:0;\n"
                                      "            font: 12pt \"Consolas\";\n"
                                      "            margin:15px;\n"
                                      "            border-bottom: 2px solid #B3B3B3;}\n"
                                      "            QLineEdit:hover{\n"
                                      "                border-bottom:3px solid #66A3FF;\n"
                                      "            }\n"
                                      "            QLineEdit:focus{\n"
                                      "                border-bottom:3px solid #E680BD\n"
                                      "            }")
        self.lineEdit_3.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_3.setDragEnabled(False)
        self.lineEdit_3.setClearButtonEnabled(True)
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.gridLayout_3.addWidget(self.lineEdit_3, 2, 0, 1, 2)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.reg)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(12)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setStyleSheet("            QLineEdit\n"
                                      "            {border:0px;\n"
                                      "            border-radius:0;\n"
                                      "            font: 12pt \"Consolas\";\n"
                                      "            margin:15px;\n"
                                      "            border-bottom: 2px solid #B3B3B3;}\n"
                                      "            QLineEdit:hover{\n"
                                      "                border-bottom:3px solid #66A3FF;\n"
                                      "            }\n"
                                      "            QLineEdit:focus{\n"
                                      "                border-bottom:3px solid #E680BD\n"
                                      "            }")
        self.lineEdit_2.setInputMask("")
        self.lineEdit_2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_2.setDragEnabled(False)
        self.lineEdit_2.setCursorMoveStyle(QtCore.Qt.LogicalMoveStyle)
        self.lineEdit_2.setClearButtonEnabled(True)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.gridLayout_3.addWidget(self.lineEdit_2, 1, 0, 1, 2)
        self.lineEdit = QtWidgets.QLineEdit(self.reg)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(12)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.lineEdit.setFont(font)
        self.lineEdit.setStyleSheet("            QLineEdit\n"
                                    "            {border:0px;\n"
                                    "            border-radius:0;\n"
                                    "            font: 12pt \"Consolas\";\n"
                                    "            margin:15px;\n"
                                    "            border-bottom: 2px solid #B3B3B3;}\n"
                                    "            QLineEdit:hover{\n"
                                    "                border-bottom:3px solid #66A3FF;\n"
                                    "            }\n"
                                    "            QLineEdit:focus{\n"
                                    "                border-bottom:3px solid #E680BD\n"
                                    "            }")
        self.lineEdit.setEchoMode(QtWidgets.QLineEdit.Normal)
        self.lineEdit.setClearButtonEnabled(True)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout_3.addWidget(self.lineEdit, 0, 0, 1, 2)
        self.label_6 = QtWidgets.QLabel(self.reg)
        self.label_6.setStyleSheet("color: rgb(255, 1, 39);\n"
                                   "font: 11pt \"宋体\";")
        self.label_6.setObjectName("label_6")
        self.gridLayout_3.addWidget(self.label_6, 3, 0, 1, 2)
        self.tabWidget.addTab(self.reg, "")
        self.gridLayout.addWidget(self.tabWidget, 2, 0, 1, 3)
        self.label_2 = QtWidgets.QLabel(self)
        font = QtGui.QFont()
        font.setFamily("Comic Sans MS")
        font.setPointSize(14)
        self.label_2.setFont(font)
        self.label_2.setStyleSheet("color: white;")
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 0, 1, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 0, 2, 1, 1)
        self.comboBox = QtWidgets.QComboBox(self)
        font = QtGui.QFont()
        font.setFamily("Prestige Elite Std")
        font.setPointSize(13)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.comboBox.setFont(font)
        self.comboBox.setStyleSheet("")
        self.comboBox.setEditable(True)
        self.comboBox.setObjectName("comboBox")
        self.gridLayout.addWidget(self.comboBox, 1, 0, 1, 2)

        self.tabWidget.setCurrentIndex(LOGIN_INFO["type"])
        QtCore.QMetaObject.connectSlotsByName(self)

        self.commandLinkButton.clicked.connect(lambda: self.tabWidget.setCurrentIndex(1))

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Dialog", "登录 - 注册"))
        self.lineEdit_5.setPlaceholderText(_translate("Dialog", "密码(4-10字符)"))
        self.lineEdit_4.setPlaceholderText(_translate("Dialog", "用户名(2-12字符)"))
        self.pushButton_2.setText(_translate("Dialog", "登录"))
        self.checkBox_2.setText(_translate("Dialog", "记住密码"))
        self.label_3.setText(_translate("Dialog", ""))
        self.commandLinkButton.setText(_translate("Dialog", "没有账号？ 注册一个"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.log), _translate("Dialog", "登录"))
        self.pushButton.setText(_translate("Dialog", "注册"))
        self.checkBox.setText(_translate("Dialog", "记住密码"))
        self.lineEdit_3.setPlaceholderText(_translate("Dialog", "再次输入密码(4-10字符)"))
        self.lineEdit_2.setPlaceholderText(_translate("Dialog", "密码(4-10字符)"))
        self.lineEdit.setPlaceholderText(_translate("Dialog", "用户名(2-12字符)"))
        self.label_6.setText(_translate("Dialog", ""))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.reg), _translate("Dialog", "注册"))
        self.label_2.setText(_translate("Dialog", "Socketserver"))
        self.comboBox.addItems(ip_list)
        self.log_progress_signal.connect(self.label_3.setText)
        self.reg_progress_signal.connect(self.label_6.setText)
        self.handle_signal.connect(self.handle)
        self.err_signal.connect(self.err_handle)

        if LOGIN_INFO["type"] == 0:
            #  login
            self.lineEdit_4.setText(LOGIN_INFO["username"])
            self.lineEdit_5.setText(LOGIN_INFO["password"])

        elif LOGIN_INFO["type"] == 1:
            self.lineEdit.setText(LOGIN_INFO["username"])
            self.lineEdit_2.setText(LOGIN_INFO["password"])
            self.lineEdit_3.setText(LOGIN_INFO["password"])

        self.pushButton.clicked.connect(self.register)
        self.pushButton_2.clicked.connect(self.login)

        self.show()

    def Enable(self, boolean):
        self.pushButton.setEnabled(boolean)
        self.pushButton_2.setEnabled(boolean)

    def get_ip(self) -> str:
        return self.comboBox.currentText()

    def clear(self):
        self.label_3.setText("")
        self.label_6.setText("")

    def login(self, *args):
        self.clear()
        self.Enable(False)
        self._login()

    def err_handle(self, string):
        self.label_3.setText(string)
        self.label_6.setText(string)
        self.Enable(True)

    def handle(self, dictionary: (dict, str)):
        self.loading_dialog.close()
        if isinstance(dictionary, dict):
            result = dictionary.get("result", False)
            reason = dictionary.get("reason", False)

            if not result:
                self.err_handle(reason)
            else:
                self.successful = True
                self.close()

        self.Enable(True)

    def login_trace(self, res: bool, reason: str):
        self.label_3.setText(reason)
        self.Enable(True)

    def loading(self) -> callable:
        self.loading_dialog = LoadingProgress(self)
        return self.loading_dialog.update_signal.emit

    def exec_loading_dialog(self):
        if isinstance(self.loading_dialog, LoadingProgress):
            self.loading_dialog.exec_()  # 直接使用造成阻塞, 为此单独调用.

    def _login(self):
        username = self.lineEdit_4.text().strip()
        password = self.lineEdit_5.text().strip()

        if not username:
            return self.login_trace(False, "未填写用户名!")
        if not password:
            return self.login_trace(False, "未填写密码!")
        if not 2 <= len(username) <= 12:
            return self.login_trace(False, "用户名需在2~12位之间!")
        if not 4 <= len(password) <= 10:
            return self.login_trace(False, "密码需在4~10位之间!")
        try:
            addr, port = self.get_ip().split(":")
            assert isinstance(addr, str)
            port = int(port)
        except (ValueError, AssertionError):
            return self.login_trace(False, "ipv4地址不正确! 结构:[host:port]")

        s.change_address(addr, port)
        s.Check_info({"type": 0, "username": username, "password": password}, self.loading(),
                     self.handle_signal.emit, self.err_signal.emit)  # self.log_progress_signal
        self.exec_loading_dialog()
        self.setEnabled(True)

        global LOGIN_INFO
        LOGIN_INFO["username"] = username
        LOGIN_INFO["password"] = password

        if self.checkBox_2.isChecked():
            json_dump()
        return True, ""

    def register(self, *args):
        self.Enable(False)
        self.clear()
        self._register()

    def register_trace(self, res: bool, reason: str):
        self.label_6.setText(reason)
        self.Enable(True)

    def _register(self):
        username = self.lineEdit.text().strip()
        password = self.lineEdit_2.text().strip()
        password_check = self.lineEdit_3.text().strip()
        if not password_check == password:
            return self.register_trace(False, "两次输入密码不同!")
        if not username:
            return self.register_trace(False, "未填写用户名!")
        if not password:
            return self.register_trace(False, "未填写密码!")
        if not 2 <= len(username) <= 12:
            return self.register_trace(False, "用户名需在2~12位之间!")
        if not 4 <= len(password) <= 10:
            return self.register_trace(False, "密码需在4~10位之间!")
        try:
            addr, port = self.get_ip().split(":")
            assert isinstance(addr, str)
            port = int(port)
        except (ValueError, AssertionError):
            return self.register_trace(False, "ipv4地址不正确! 结构:[host:port]")

        s.change_address(addr, port)
        s.Check_info({"type": 1, "username": username, "password": password}, self.loading(),
                     self.handle_signal.emit, self.err_signal.emit)  # self.reg_progress_signal
        self.exec_loading_dialog()

        global LOGIN_INFO
        LOGIN_INFO["username"] = username
        LOGIN_INFO["password"] = password

        if self.checkBox.isChecked():
            json_dump()
        return True, ""


class MainTalk(QtWidgets.QMainWindow):
    ConnectionError_signal = QtCore.pyqtSignal()
    MessageUpdate_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super(MainTalk, self).__init__()
        self.ConnectionError_signal.connect(self.ConnectionError)
        self.MessageUpdate_signal.connect(self.Show_Message)

        self.is_setup = False

    def SetupUi(self):
        self.anim = Animation(self)
        self.setObjectName("MainWindow")
        self.resize(800, 619)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        self.setFont(font)
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_3.setReadOnly(True)
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.gridLayout.addWidget(self.lineEdit_3, 7, 3, 1, 1)
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setStyleSheet("background-color:rgb(44, 176, 13);\n"
                                      "color:rgb(255, 255, 255);\n"
                                      "font: 200 10pt \"Consolas\";")
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 8, 6, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 8, 5, 1, 1)
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 6, 1, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem1, 8, 3, 1, 1)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_2.setReadOnly(True)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.gridLayout.addWidget(self.lineEdit_2, 6, 3, 1, 1)
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 5, 1, 1, 1)
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setCursor(QtGui.QCursor(QtCore.Qt.IBeamCursor))
        self.lineEdit.setDragEnabled(False)
        self.lineEdit.setReadOnly(True)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout.addWidget(self.lineEdit, 5, 3, 1, 1)
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3, 7, 1, 1, 1)
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.gridLayout.addWidget(self.line, 5, 4, 3, 1)
        self.textEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit.setObjectName("textEdit")
        self.gridLayout.addWidget(self.textEdit, 5, 5, 3, 2)
        spacerItem2 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem2, 1, 1, 1, 1)
        self.textEdit_2 = QtWidgets.QTextBrowser(self.centralwidget)
        self.textEdit_2.setObjectName("textEdit_2")
        self.textEdit_2.setReadOnly(True)
        self.gridLayout.addWidget(self.textEdit_2, 0, 3, 2, 4)
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setObjectName("pushButton_2")
        self.sendButton = QtWidgets.QPushButton(QtGui.QIcon("images/upload.png"), "上传文件", self.centralwidget)
        self.sendButton.setObjectName("send - pushButton")
        self.gridLayout.addWidget(self.sendButton, 8, 5)
        self.gridLayout.addWidget(self.pushButton_2, 8, 1, 1, 1)
        self.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(self)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 24))
        self.menubar.setObjectName("menubar")
        self.menu = QtWidgets.QMenu(self.menubar)
        self.menu.setObjectName("menu")
        self.menulanguage = QtWidgets.QMenu(self.menu)
        self.menulanguage.setObjectName("menulanguage")
        self.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        self.actionsocket_connet = QtWidgets.QAction(self)
        self.actionsocket_connet.setObjectName("actionsocket_connet")
        self.actionChinese = QtWidgets.QAction(self)
        self.actionChinese.setObjectName("actionChinese")
        self.actionip_socket_gethostbyname_socket_gethostname = QtWidgets.QAction(self)
        self.actionip_socket_gethostbyname_socket_gethostname.setObjectName(
            "actionip_socket_gethostbyname_socket_gethostname")
        self.menulanguage.addSeparator()
        self.menulanguage.addAction(self.actionChinese)
        self.menu.addSeparator()
        self.menu.addAction(self.menulanguage.menuAction())
        self.menu.addAction(self.actionip_socket_gethostbyname_socket_gethostname)
        self.menubar.addAction(self.menu.menuAction())
        self.socket_peername = s.addr[0]
        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)
        self.pushButton.clicked.connect(self.send("MSG"))
        self.pushButton_2.clicked.connect(self.re_connect)
        self.textEdit.textChanged.connect(self.tc)
        self.textEdit_2.setOpenLinks(False)
        self.textEdit_2.setOpenExternalLinks(False)
        self.textEdit_2.anchorClicked.connect(self.anchor)
        self.sendButton.clicked.connect(self.send("FILE"))
        self.connectEnabled(True)
        self.is_setup = True
        self.show()

    @staticmethod
    def anchor(res: QtCore.QUrl):
        index = res.toString()
        s.handler.request_file(index)

    @to_logging
    def sendfile(self):
        for file in QtWidgets.QFileDialog.getOpenFileNames(self, "上传文件")[0]:
            if os.path.isfile(file):
                s.handler.send(file)

    @to_logging
    def sendmsg(self):
        s.handler.send_text(self.textEdit.toPlainText().strip())
        self.textEdit.clear()

    def tc(self, _=0):
        if 0 < len(self.textEdit.toPlainText().strip()) <= 1000:
            self.pushButton.setEnabled(True)
        else:
            self.pushButton.setEnabled(False)
        self.pushButton.setText(
            QtCore.QCoreApplication.translate("MainWindow", f"发送({len(self.textEdit.toPlainText().strip())} / 1000)"))

    def send(self, _type):
        _call = {"MSG": self.sendmsg, "FILE": self.sendfile}.get(_type, lambda: True)

        @to_logging
        def function(_):
            if s.is_connect():
                if not _call():
                    self.ConnectionError_signal.emit()
            else:
                self.MessageUpdate_signal.emit("<font color='red'>发送异常. 未连接至服务器.请点击[重新连接服务器]按钮尝试重新连接.</font>")

        return function

    def ConnectionError(self):
        QtWidgets.QMessageBox.information(self, 'TraceBack', f'Socket Server<{self.socket_peername}> 断开连接')
        self.connectEnabled(False)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "Socket"))
        self.lineEdit_2.setText(socket.gethostname())
        self.lineEdit.setText(socket.gethostbyname(socket.gethostname()))
        self.lineEdit_3.setText(self.socket_peername)
        self.tc()
        self.label_2.setText(_translate("MainWindow", "主机名:"))
        self.label.setText(_translate("MainWindow", "本地端口:"))
        self.label_3.setText(_translate("MainWindow", "连接端口:"))
        self.pushButton_2.setText(_translate("MainWindow", "重新连接服务器"))
        self.menu.setTitle(_translate("MainWindow", "设置"))
        self.menulanguage.setTitle(_translate("MainWindow", "language"))
        self.actionsocket_connet.setText(_translate("MainWindow", "socket connect"))
        self.actionChinese.setText(_translate("MainWindow", "Chinese"))
        self.MessageUpdate_signal.emit(f'<font color="red">欢迎来到服务器[{s.socket.getpeername()[0]}].您的ip地址为{s.addr[0]}')
        self.actionip_socket_gethostbyname_socket_gethostname.setText(
            _translate("MainWindow", "ip: " + socket.gethostbyname(socket.gethostname())))
        s.set_failEvent(self.MessageUpdate_signal.emit)
        s.run()

    @to_logging
    def re_connect(self, _):
        self.MessageUpdate_signal.emit(
            "[{}]: 尝试连接服务器[{}],最大超时报错 {}s".format(datetime.now().strftime('%Y %m %d %H:%M:%S'), s.addr[0], TIMEOUT))
        QtWidgets.QApplication.processEvents()

        s.set_failEvent(self.MessageUpdate_signal.emit)
        status = s.connect()
        self.connectEnabled(status)
        if status:
            s.run()

    def connectEnabled(self, status):
        self.pushButton_2.setEnabled(not status)

    def Show_Message(self, data: str) -> None:
        # self.MessageUpdate_signal -> [signal]; self.MessageUpdate_signal.emit(self, *args, **kwargs). #
        if data:
            for i in data.split('\n'):
                if i:
                    sleep(0.06 / len(data.split('\n')))  # 防止信息过快使Textedit刷新空白
                    self.textEdit_2.append(i)
        self.textEdit_2.moveCursor(QtGui.QTextCursor.End)


def save_bytes(file, byte: bytes):
    with open(file, "wb") as f:
        f.write(byte)


def get_eval(string, defined=None):
    try:
        res = eval(string)
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
        self.fd_index = len(file_dialog.filedict)  # pyqtSignal无返回值
        file_dialog.new_file.emit([self.name, self.total, self.size, (file_dialog.UPLOAD, localfile)])

    async def update(self):
        self.conn(self.header().encode(self.encode))
        with open(self.localfile, "rb") as f:
            for n in range(self.total):
                self.conn(self.format(n, f.read(segment)).encode(self.encode))
                file_dialog.update_file.emit(self.fd_index)
                await asyncio.sleep(delay)
        self.finish = True

    @staticmethod
    def cut(byte: bytes, seg=segment) -> list:
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
        self.fd_index = len(file_dialog.filedict)  # pyqtSignal无返回值
        self.save_path = os.path.join(save_path, self.name)
        file_dialog.new_file.emit(
            [self.name, self.total, self.size, (file_dialog.DOWNLOAD, os.path.join(save_path, self.name))])

    def update(self, p, data):
        if isinstance(p, int) and p - 1 == self.progress:
            self.progress = p
            self.file.append(data)
            self.update_file()
            file_dialog.update_file.emit(self.fd_index)
            if len(self.file) == self.total:
                logging.info(f"Save {self.name} at {self.save_path}, size {self.size} b.")
                self.finish = True
                return True

    def update_file(self):
        with open(self.save_path, "ab") as f:
            f.write(self.file[-1])

    def save(self):
        return self.finish

    def savepath(self) -> (str, bool):
        if self.finish:
            return self.save_path
        return False

    def start(self):
        if self.finish:
            os.startfile(self.savepath())


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

    def get_index(self,
                  index: int) -> RECV:  # 致命bug, 如若用self.recvs[index] 排序方法不一， 用户端不可能从第一个文件开始请求， 然后排着序请求1,2,3,4,5,6... 一个不能少， 所以用以下方法
        for x in self.recvs:
            if x.index == index:
                return x

    def in_list(self, index) -> bool:
        return bool(self.get_index(index))

    def update(self, index, progess, data) -> bool:
        if self.in_list(index):
            if self.get_index(index).update(progess, data):
                return self.save(index)

    def save(self, index):
        if self.in_list(index):
            return self.get_index(index).save()


class message_handle:
    codec = "utf8"

    def __init__(self, func: callable = lambda _: True):
        self.Sender = send_files(self.codec, )
        self.Receiver = recv_files(self.codec, save_path)
        self.func = func
        self.Progress = []

    def handle(self, data):
        _res = get_eval(data, (None,))
        if len(_res) == 2:
            type, arguments = _res
            if type == new_file:
                self.Receiver.new_files(*arguments)
                return
            elif type == update_file:
                self.Receiver.update(*arguments)
                return
            elif type == request_file:
                path = self.Receiver.get_index(arguments).savepath()
                if path:
                    self.Sender.localfile(path, self.func)  # 如若无, 报错False
                return
            elif type == normal_text:
                return arguments

        logging.info("Parsing error.")

    def send(self, sendpath):
        return self.Sender.localfile(sendpath, self.func)

    def send_text(self, mes: str):
        return self.func(repr((normal_text, mes)).encode(self.codec))

    def request_file(self, name):
        index = get_eval(name, 0)
        if self.in_list(index):
            self.get_index(index).start()
            return
        self.func(repr((request_file, index)).encode(self.codec))

    def get_index(self, index) -> RECV:
        return self.Receiver.get_index(index)

    def in_list(self, index):
        return self.Receiver.in_list(index)


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
    1EB（Exabyte 百亿亿字节 艾字节）=1024PB"""
    if not isinstance(byte, (int, float)):
        byte = len(byte)
    DEI = f"{byte} bytes"
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


class ListWidgetLayout(QtWidgets.QWidget):
    def __init__(self, name, total, size, parent=None):
        super(ListWidgetLayout, self).__init__(parent)
        self.size = size
        self.total = total
        self.segment = math.ceil(self.size // self.total)
        self.index = 0

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


class FileDialog(QtWidgets.QDialog):
    update_file = QtCore.pyqtSignal(int)
    new_file = QtCore.pyqtSignal(list)

    def __init__(self, save_path, parent=None):
        self.path = None
        self.fpath = None
        self.current = ""
        super(FileDialog, self).__init__(parent)
        self.icon = QtGui.QIcon("images/file.png")
        self.download = QtGui.QIcon("images/download.png")
        self.upload = QtGui.QIcon("images/upload.png")
        self.DOWNLOAD = 0
        self.UPLOAD = 1
        self.LOAD_dict = {self.DOWNLOAD: self.download,
                          self.UPLOAD: self.upload}

        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint)  # 只显示最小化按钮
        self.save_path = save_path
        self.filedict = {}
        self.pathdict = {}
        self.namedict = {}
        self.update_file.connect(self.fileUpdate)
        self.new_file.connect(self.newFile)
        self.setObjectName("Dialog")
        self.resize(666, 421)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        self.setFont(font)
        self.setWindowIcon(self.icon)
        self.gridLayout = QtWidgets.QGridLayout(self)
        self.gridLayout.setObjectName("gridLayout")
        self.label_4 = QtWidgets.QLabel(self)
        self.label_4.setObjectName("label_4")
        self.gridLayout.addWidget(self.label_4, 1, 2, 1, 1)
        self.listWidget_2 = QtWidgets.QListWidget(self)
        self.listWidget_2.setObjectName("listWidget_2")
        self.gridLayout.addWidget(self.listWidget_2, 0, 0, 4, 1)
        self.groupBox = QtWidgets.QGroupBox(self)
        self.groupBox.setObjectName("groupBox")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.groupBox)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.label = QtWidgets.QLabel(self.groupBox)
        self.label.setObjectName("label")
        self.gridLayout_2.addWidget(self.label, 1, 0, 1, 2)
        self.progressBar = QtWidgets.QProgressBar(self.groupBox)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        self.progressBar.setFont(font)
        self.progressBar.setProperty("value", 0)
        self.progressBar.setTextVisible(True)
        self.progressBar.setObjectName("progressBar")
        self.gridLayout_2.addWidget(self.progressBar, 0, 0, 1, 2)
        self.label_3 = QtWidgets.QLabel(self.groupBox)
        self.label_3.setObjectName("label_3")
        self.gridLayout_2.addWidget(self.label_3, 2, 0, 1, 2)
        self.pushButton = QtWidgets.QPushButton(self.groupBox)
        self.pushButton.setObjectName("pushButton")
        self.pushButton.setEnabled(False)
        self.gridLayout_2.addWidget(self.pushButton, 4, 0, 1, 1)
        self.label_2 = QtWidgets.QLabel(self.groupBox)
        self.label_2.setObjectName("label_2")
        self.gridLayout_2.addWidget(self.label_2, 3, 0, 1, 2)
        self.pushButton_2 = QtWidgets.QPushButton(self.groupBox)
        self.pushButton_2.setObjectName("pushButton_2")
        self.gridLayout_2.addWidget(self.pushButton_2, 4, 1, 1, 1)
        self.gridLayout.addWidget(self.groupBox, 0, 2, 1, 1)
        self.lineEdit = QtWidgets.QLineEdit(self)
        self.lineEdit.setReadOnly(True)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout.addWidget(self.lineEdit, 2, 2, 1, 1)
        self.line = QtWidgets.QFrame(self)
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.gridLayout.addWidget(self.line, 0, 1, 4, 1)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem, 3, 2, 1, 1)

        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Dialog", "Files"))
        self.pushButton.setText(_translate("Dialog", "打开"))
        self.pushButton_2.setText(_translate("Dialog", "打开文件夹"))
        self.pushButton.clicked.connect(self.startfile)
        self.pushButton_2.clicked.connect(self.startpath)
        self.label_4.setText(_translate("Dialog", f"下载位置:"))
        self.lineEdit.setText(_translate("Dialog", self.save_path))

        self.listWidget_2.itemClicked.connect(self.fileChanged)

    def newFile(self, args: list):
        self.activateWindow()  # 窗口置顶

        index = len(self.filedict)
        name, total, size, (_type, path) = args

        png = self.LOAD_dict.get(_type, self.UPLOAD)
        layout = ListWidgetLayout(name, total, size)
        progress = layout.get_progress()
        self.filedict[index] = (layout, size)
        self.pathdict[index] = path
        Item = QtWidgets.QListWidgetItem(png, "", self.listWidget_2)
        Item.index_name = index  # <-
        Item.setSizeHint(QtCore.QSize(200, 80))
        self.listWidget_2.addItem(Item)
        self.listWidget_2.setItemWidget(Item, layout)

        self.namedict[index] = name
        # if not self.current:
        #    self.changeCurrent(0)
        self.changeCurrent(index)

    def changeCurrent(self, index: int):
        self.current = index
        self.changeGroupBox()
        self.show()

    def fileChanged(self, widget: QtWidgets.QListWidgetItem):
        self.current = widget.index_name
        self.changeGroupBox()

    def changeGroupBox(self):
        name = self.namedict[self.current]
        layout, size = self.filedict[self.current]
        layout: ListWidgetLayout
        size = convert(size, True)
        _translate = QtCore.QCoreApplication.translate
        self.groupBox.setTitle(_translate("Dialog", f"{name}"))
        self.label.setText(_translate("Dialog", f"文件大小: {size}"))
        self.label_3.setText(_translate("Dialog", f"文件名: {name}"))
        self.label_2.setText(_translate("Dialog", f"位置: {os.path.join(self.save_path, name)}"))

        self.progressBar.setMaximum(layout.get_total())
        self.progressBar.setValue(layout.get_index())
        self.pushButton.setEnabled(layout.is_finished())
        self.fpath = self.pathdict[self.current]
        self.path = os.path.dirname(self.fpath)

    def fileUpdate(self, index: int):
        layout, size = self.filedict[index]
        layout: ListWidgetLayout
        layout.update()
        if index == self.current:
            self.changeGroupBox()

    def startfile(self, _):
        if hasattr(self, "fpath") and os.path.isfile(self.fpath):
            os.startfile(self.fpath)

    def startpath(self, _):
        if hasattr(self, "path") and os.path.isdir(self.path):
            os.startfile(self.path)


if __name__ == "__main__":
    save_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "resource")
    if not os.path.isdir(save_path):
        os.makedirs(save_path)

    file_thread.start()
    s = Socket()

    app = QtWidgets.QApplication(sys.argv)
    if "fusion" in QtWidgets.QStyleFactory.keys():
        app.setStyle("fusion")
    conn = User_Setup()
    main = MainTalk()
    file_dialog = FileDialog(save_path)
    sys.exit(app.exec_())
