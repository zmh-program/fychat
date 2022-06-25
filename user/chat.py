import os
import sys
import logging
import time

from PyQt5 import QtWebEngineWidgets, QtCore, QtWidgets, QtGui


def convert(byte, fine=False):
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
        byte /= 1024
        index += 1

    if index == 0:
        return DEI
    else:
        if fine:
            return "%0.1f%s(%s)" % (byte, units[index], DEI)
        else:
            return "%0.1f%s" % (byte, units[index])


def to_logging(command):
    def logs(*args, **kwargs):
        try:
            _result = command(*args, **kwargs)
            if _result is None:
                return True
            return _result
        except:
            logging.exception("")

    return logs


with open("chat.html", "r", encoding="utf-8") as f:
    html = f.read()


def omit(string: str, max_length: int, d_text: str = "...") -> str:
    if len(d_text) > max_length:
        d_text = d_text[: max_length]

    if len(string) > max_length:
        return string[:max_length - len(d_text)] + d_text
    return string


class ImageLoader:
    path = "images/filetype"
    unkown = os.path.join(path, "unknown.png").replace("\\", "/")
    filedict = {}

    def __init__(self):
        for filename in os.listdir(self.path):
            filepath = self.join(filename)
            filetype, _ = os.path.splitext(filename)
            self.filedict[filetype.lower()] = filepath

    def join(self, filename):
        return os.path.join(self.path, filename).replace("\\", "/")

    def get_suffix_img(self, suf):
        return self.filedict.get(suf, self.unkown)

    @staticmethod
    def get_suf(filename):
        _, suf = os.path.splitext(filename)
        return suf.lstrip(".").lower()

    def get(self, filename):
        return self.get_suffix_img(self.get_suf(filename))


class QChatWidget(QtWebEngineWidgets.QWebEngineView):
    img = ImageLoader()
    anchorClicked = QtCore.pyqtSignal(int)
    user_message = QtCore.pyqtSignal(bool, str, str)
    server_message = QtCore.pyqtSignal(str)
    add_file = QtCore.pyqtSignal(str, str, bool, str, int)
    boundary_time = 60 * 5

    def __init__(self, parent=None):
        super(QChatWidget, self).__init__(parent)
        self.setWindowTitle('chat')
        self.setGeometry(5, 30, 468, 662)
        self.load(QtCore.QUrl(QtCore.QFileInfo("chat.html").absoluteFilePath()))
        self.startTimer(100)
        self.anchor = -1
        self.user_message.connect(self._user_message)
        self.server_message.connect(self._server_message)
        self.add_file.connect(self._add_file)
        self.record_time = 0

    def timerEvent(self, *args) -> None:
        self.JavaScript(f"height_changed({self.size().height()});")
        self.JavaScript("get_anchor();", self.checkAnchor)

    def check_time(self):
        if time.time() - self.record_time > self.boundary_time:
            self.record_time = time.time()
            self.JavaScript(f"time({repr(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.record_time)))})")

    def checkAnchor(self, index: int):
        """
        function set_anchor( index ) {
            _link = index
        }
        function reset_anchor() {
            set_anchor(-1);
        }

        function get_anchor() {
            return _link;
        }
        """
        if isinstance(index, int) and index != self.anchor:
            self.anchorClicked.emit(index)
            self.JavaScript("reset_anchor();")

    def JavaScript(self, *args, **kwargs):
        self.page().runJavaScript(*args, **kwargs)

    def _user_message(self, _is_self: bool, content: str, name: str):
        """ function user_message(name, content, is_self); """
        self.check_time()
        self.JavaScript(f"user_message({repr(name)}, {repr(omit(content, 400))}, {str(_is_self).lower()});")

    def _server_message(self, content: str):
        """ function server_message(content); """
        self.check_time()
        self.JavaScript(f"server_message({repr(content)});")

    def _add_file(self, filename: str, size: str, _is_self: bool, name: str, index: int):
        """ function file(filename, _size, ico_path, link, username, is_self); """
        ico_path = self.img.get(filename)
        filename = omit(filename, 50)
        self.check_time()
        self.JavaScript(
            f"file({repr(filename)}, {repr(size)}, {repr(ico_path)}, {index}, {repr(name)}, {str(_is_self).lower()});")

    def contextMenuEvent(self, a0: QtGui.QContextMenuEvent) -> None:
        pass


class QChat(QtWidgets.QWidget):
    def __init__(self, parent=None, username=""):
        super(QChat, self).__init__(parent)
        self.setObjectName("Form")
        self.username = username
        self.resize(591, 670)
        self.gridLayout = QtWidgets.QGridLayout(self)
        self.gridLayout.setObjectName("gridLayout")
        self.web = QChatWidget(self)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(12)
        self.web.setFont(font)
        self.web.setObjectName("web")
        self.gridLayout.addWidget(self.web, 2, 1, 2, 1)
        self.line_2 = QtWidgets.QFrame(self)
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.gridLayout.addWidget(self.line_2, 1, 1, 1, 1)
        self.textEdit = QtWidgets.QTextEdit(self)
        self.textEdit.setObjectName("textEdit")
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(13)
        self.textEdit.setFont(font)
        self.gridLayout.addWidget(self.textEdit, 4, 1, 1, 1)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.uploadButton = QtWidgets.QPushButton(self)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        self.uploadButton.setFont(font)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("images/upload.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.uploadButton.setIcon(icon)
        self.uploadButton.setObjectName("uploadButton")
        self.horizontalLayout.addWidget(self.uploadButton)
        self.sendButton = QtWidgets.QPushButton(self)
        self.sendButton.setEnabled(False)
        self.sendButton.setStyleSheet("""
QPushButton{
    background:#fffff;
    border-size: 0;
}
QPushButton:hover{
    background: rgb(205, 205, 205);
}""")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("images/send.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.sendButton.setIcon(icon1)
        self.sendButton.setObjectName("sendButton")
        self.horizontalLayout.addWidget(self.sendButton)
        self.gridLayout.addLayout(self.horizontalLayout, 5, 1, 1, 1)
        self.line = QtWidgets.QFrame(self)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.gridLayout.addWidget(self.line, 3, 1, 1, 1)
        self.label = QtWidgets.QLabel(self)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(20)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 1, 1, 1)

        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)
        self.textEdit.textChanged.connect(self.textChanged)
        self.sendButton.clicked.connect(self.send)
        self.uploadButton.clicked.connect(self.sendfile)
        self.sendButton.setStyleSheet("""
    QPushButton
    {
    border-size: 10px solid rgb(200, 200, 200);
    border-radius: 15px;
    padding: 5px 10px 5px 10px;
    border: 2px groove gray;border-style: outset;
    }
    QPushButton:hover{background:rgb(220, 220, 220);}
    QPushButton:pressed{background:rgb(210, 210, 210);}
    """)
        self.uploadButton.setStyleSheet("""
    QPushButton
    {
    border-size: 10px solid rgb(200, 200, 200);
    border-radius: 15px;
    padding: 5px 10px 5px 10px;
    border: 2px groove gray;
    border-style: outset;
    }
    QPushButton:hover{background:rgb(220, 220, 220);}
    QPushButton:pressed{background:rgb(210, 210, 210);}
    """)

    def user_message(self, _is_self: bool, content: str, name: str):
        self.web.user_message.emit(_is_self, content, name)

    def server_message(self, content: str):
        self.web.server_message.emit(content)

    def add_file(self, filename: str, size: str, _is_self: bool, name: str, index: int):
        self.web.add_file.emit(filename, size, _is_self, name, index)

    def getText(self) -> str:
        return self.textEdit.toPlainText().strip()

    def send(self) -> None:
        self.user_message(True, self.getText(), self.username)  ##
        self.textEdit.clear()

    def textChanged(self, *args) -> None:
        self.sendButton.setEnabled(0 < len(self.getText()) < 400)

    def setTitle(self, title: str) -> None:
        self.label.setText(QtCore.QCoreApplication.translate("Form", title))

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Form", "Form"))
        self.sendButton.setText(_translate("Form", "发送"))
        self.uploadButton.setText(_translate("Form", "上传"))
        self.setTitle("ZServer - Chat")

    def sendfile(self, *args):
        for file in QtWidgets.QFileDialog.getOpenFileNames(self, "上传文件")[0]:
            if os.path.isfile(file):  ##
                path, filename = os.path.split(file)
                self.add_file(filename, convert(os.path.getsize(file)), True, self.username, 0)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    win = QChat(username="user1")
    win.show()
    app.exit(app.exec_())
