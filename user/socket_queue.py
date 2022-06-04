import socket
from datetime import datetime

get_time = lambda: datetime.now().strftime('%H:%M:%S')
TIMEOUT = 2


def ignore(function):
    def func(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except:
            pass

    return func


class SocketQueue:
    split_text = "\n"  # 类变量， 默认分隔符为回车(\n)

    class QuitError(ConnectionError):
        pass

    def __init__(self, sock=socket.socket(), bufsize=1024, codec="utf8"):
        self.socket, self.bufsize, self.codec = sock, bufsize, codec
        self.waitKey = str()
        self.ReadyQueue = []
        self._closed = False

    def re_setup(self):
        self.waitKey = str()
        self.ReadyQueue = []
        self._closed = False

    def __close__(self):
        self.quit()

    def __del__(self):
        self.quit()

    def isOpen(self) -> bool:
        return not (self._closed and getattr(self.socket, "_closed", False))

    def quitEvent(self) -> None:
        pass

    def quit(self) -> None:
        if not self._closed:
            self._closed = True
            self.quitEvent()
            self.socket.close()

    def normal_text(self, string: str):
        return string.encode(self.codec)

    def __recv(self) -> (bytes, ConnectionError):
        try:
            data = self.socket.recv(self.bufsize).strip(b" ")  # str.strip()不可用! 会将\n省略
            if data:
                self.parse_data(self.handle(data))
        except (ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, OSError) as e:
            if isinstance(e, socket.timeout):
                return
            self.quit()
            return self.QuitError

    def __send(self, data: bytes) -> bool:
        try:
            self.socket.sendall(data)
            return True
        except (ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, OSError) as e:
            self.quit()
            return False

    def send(self, data) -> bool:
        if isinstance(data, str):
            data = self.normal_text(data)
        elif isinstance(data, (set, list, tuple)):
            data = repr(data).encode(self.codec)
        elif isinstance(data, (int, float)):
            data = str(data).encode(self.codec)
        elif isinstance(data, bytes):
            pass
        else:
            data = bytes(data)
        return self.__send(data + self.split_text.encode(self.codec))

    def input(self, text):
        self.send(text)
        return self.recv()

    def forever_receive(self) -> (str, None):
        while self.isOpen():
            self.recv()

    def handle(self, data: bytes):
        return [d.strip() for d in data.decode(self.codec).split(self.split_text)]

    @ignore
    def parse_data(self, generator: (tuple, list, set)) -> None:
        generator = list(generator)
        if len(generator) == 1:  # 列表为1, 表明无间隔符, 则在等待中添加.
            self.waitKey += generator[0]
            return
        self.ReadyQueue.append(self.waitKey + generator.pop(0))
        self.waitKey = generator.pop()
        self.ReadyQueue.extend(generator)

    def recv(self) -> (str, Exception):
        while True:
            while (not self.ReadyQueue) and self.isOpen():
                self.__recv()
            if not self.isOpen():
                return self.QuitError
            data = self.parse_argument(self.ReadyQueue.pop(0))
            if isinstance(data, str) and data:
                return data

    def parse_argument(self, arg: str) -> str:
        return arg.strip()

    def recv_list(self) -> list:
        queue = self.ReadyQueue[:]
        self.ReadyQueue = []
        return queue

    @ignore
    def connect(self, host: str, port: int):
        assert 0 <= port <= (2 ** 16) - 1
        self.socket.connect((host, port))


def err_connect(sock, addr: tuple) -> (str, bool):
    try:
        sock.connect(addr)
    except socket.gaierror:
        return f"获取地址信息失败.请确保{addr[0]}是有效地址或ipv4/ipv6"
    except socket.timeout:
        return f"连接超时({TIMEOUT}s).服务器[{addr[0]}:{addr[1]}]连接失败."
    except OverflowError:
        return f"输入的端口号为{addr[1]},端口号必须在0~65535间."
    except (ConnectionError, ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError):
        return "请求拒绝."
    except OSError as e:
        if int(addr[1]) == 0:
            return "[WinError 10049] 在其上下文中，该请求的地址无效"
        return str(e.args[1]).rstrip('。')
    except TypeError:
        return f"网络地址格式错误: 格式[ip:port] port必须为整型变量0~65535间."
    except:
        return "连接错误"
    else:
        return True


class SocketClient(SocketQueue):
    addr = "localhost", 429
    header = ""

    def __init__(self, *args, **kwargs):
        super(SocketClient, self).__init__(*args, **kwargs)
        self.socket.settimeout(TIMEOUT)
        self.connected = False
        self.__is_connect = False
        self.addr = tuple()
        self._traceback = lambda *_: None

    def is_connect(self) -> bool:
        return self.__is_connect

    def change_address(self, host: str, port: int):
        self.addr = host, port

    def change_header(self, header: str):
        self.header = header

    def set_failEvent(self, function):
        self._traceback = function

    def failEvent(self, reason):
        self._traceback(f"[{get_time()}]: {reason}")

    def connect(self):
        if self.connected:
            self.socket = socket.socket()
            self.socket.settimeout(TIMEOUT)
            self.re_setup()
        self.connected = True

        _res = err_connect(self.socket, self.addr)
        if _res is True:
            self.__is_connect = True
            _res = "连接服务器成功, 向服务器发送数据中..."
        else:
            self.failEvent(_res)
            self.__is_connect = False
            _res = str(_res)
        return self.__is_connect, _res

    def quitEvent(self) -> None:
        self.__is_connect = False

