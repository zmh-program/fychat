from json import load, dump, decoder
from os import path, mkdir, listdir
from hashlib import md5
from time import time
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def _mkdir(_folder):
    try:
        if not path.exists(_folder):
            mkdir(_folder)
            return True
    except NotImplementedError:
        logger.exception("")
    return False


def encode(_data: str):
    m = md5()
    m.update(_data.encode('utf8'))
    return m.hexdigest()


def timeit(objname: str, ign=True, _show_detail=True):
    def setup_function(func_name):
        def _exec_function(*args, **kwargs):
            startime = time()
            _resp = func_name(*args, **kwargs)
            if _show_detail:
                logger.info("Execute the function %s%s, timeit %0.3f" % (
                    objname.title(), "" if ign else f" (at {str(func_name)})", time() - startime))
            return _resp

        return _exec_function

    return setup_function


folder = r'.\clients'
_mkdir(folder)

data = set()
if path.isdir(folder):
    try:
        data = set(listdir(folder))
    except decoder.JSONDecodeError:
        pass


def __in__(username) -> bool:
    return encode(username) in data


def register(username, password, register_time: (int, float) = time()) -> None:
    global data
    data.add(username)
    user_path = path.join(folder, encode(username))
    print(user_path, _mkdir(user_path))
    _mkdir(user_path)
    with open(path.join(user_path, "user.json"), "w") as f:
        dump({"username": username, "password": password, "register_time": int(register_time)}, f, indent=4)


def login(username, password) -> bool:
    with open(path.join(path.join(folder, encode(username)), "user.json"), "r") as f:
        _data = load(f)
        return _data.get("username", "") == username and _data.get("password", "") == password


def get_time(username):
    with open(path.join(path.join(folder, encode(username)), "user.json"), "r") as f:
        return load(f).get("register_time")


@timeit("User Handle", _show_detail=True)
def handler(_type: int, username: str, password: str):
    try:
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
        if _type == 0:  # login
            if not __in__(username):
                return False, "用户不存在!", ""
            if not login(username, password):
                return False, "用户名 / 密码错误!", ""
            return True, "欢迎回来, " + username, username
        elif _type == 1:  # register
            if __in__(username):
                return False, "已存在用户!", ""
            register(username, password)
            return True, "初来乍到, " + username, username
    except Exception as e:
        logger.exception("")
        return False, str(e.__class__), ""
