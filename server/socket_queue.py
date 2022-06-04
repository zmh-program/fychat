import socket


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

    def __init__(self, socket=socket.socket(), bufsize=1024, codec="utf8"):
        self.socket, self.bufsize, self.codec = socket, bufsize, codec
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
            data = repr(data)
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
            while not self.ReadyQueue:
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
