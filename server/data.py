from json import load, dump
from os import path, mkdir
from hashlib import md5
from time import time


def encode(data: str):
    m = md5()
    m.update(data.encode('utf8'))
    return m.hexdigest()


file = '.\clients\data.json'
folder = '.\clients'
if not path.exists(folder):
    mkdir(folder)


class data:
    def __init__(self):
        if path.exists(file):
            with open(file, 'r') as f:
                self.data = load(f)
        else:
            self.data = {}

    def __get__(self, username, default=None) -> tuple:
        return self.data.get(username, default)

    def __in__(self, username) -> bool:
        return username in self.data.keys()

    def __write__(self) -> None:
        with open(file, 'w') as f:
            dump(self.data, f, indent=4)

    def __register__(self, username, password, time: (int, float) = time()) -> None:
        self.data[username] = (encode(password), int(time))
        self.__write__()

    def __login__(self, username, password) -> bool:
        return self.data[username][0] == encode(password)

    def get_time(self, username):
        return self.data[username][1]

    def handler(self, type: int, username: str, password: str):
        username = username.strip()
        if not username:
            return False, "未填写用户名!", ""
        password = password.strip()
        if not password:
            return False, "未填写密码!", ""
        if not 2 <= len(username) <= 12:
            return False, "用户名需在2~12位之间!", ""
        if not 4 <= len(password) <= 10:
            return False, "密码需在4~10位之间!", ""
        if type == 0:  # login
            if not self.__in__(username):
                return False, "用户不存在!", ""
            if not self.__login__(username, password):
                return False, "用户名 / 密码错误!", ""
            return True, "欢迎回来, " + username, username
        elif type == 1:  # register
            if self.__in__(username):
                return False, "已存在用户!", ""
            self.__register__(username, password)
            return True, "初来乍到, " + username, username
