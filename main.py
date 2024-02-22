# 2023/12/04 nzg
# try to login automatically because of the brilliant login system

import requests
import time
from logging import *
import json
import re
import hmac
import hashlib
import urllib.parse
import tomllib


class User:
    def __init__(self, name, password):
        self._name = name
        self._password = password

    @property
    def name(self):
        return self._name

    @property
    def password(self):
        return self._password


class College:
    def __init__(self, host, alpha, mystery_number):
        self.host = host
        self.alpha = alpha
        self.mystery_number = mystery_number


def read_config(path: str = './config.toml') -> tuple[User, College]:
    with open(path, 'rb') as f:
        config = tomllib.load(f)
        user = User(**config['authentication'])
        coll = College(**config['general'])
        return user, coll


# steps:
#   1. get the challenge
#   2. meet the challenge
#   3. send the login request


def get_challenge(name: str, pswd: str, college: College) -> dict[str, str]:
    timestamp = int(time.time() * 1000)
    mystery = college.mystery_number
    url = (
        f"{college.host}/cgi-bin/get_challenge?"
        f"callback=jQuery{mystery}_{timestamp}&username={name}&_={timestamp}"
    )

    try:
        info(f'Req url: {url}')
        resp = requests.get(url)
        info(f'Res: {resp.text}')
    except requests.RequestException as e:
        error(f"HTTP request failed: {e}")
        exit(1)

    response_format = re.compile(r"(jQuery\d+_\d+)\((.*)\)")
    match = response_format.match(resp.text)
    if not match:
        error("Regex match failed")
        exit(1)

    prefix = match.group(1)
    response_content = match.group(2)
    info(response_content)

    try:
        response_json = json.loads(response_content)
    except json.decoder.JSONDecodeError:
        error("JSON decode error: bad format")
        exit(1)

    if not isinstance(response_json, dict):
        error("JSON decode error: not a dict")
        exit(1)

    # Add more info to response
    response_json["username"] = name
    response_json["password"] = pswd
    response_json["prefix"] = prefix
    response_json["timestamp"] = timestamp

    return response_json


# write by good GPT ♥
def calculate_hmac_md5(key, message):
    # Ensure key and message are bytes
    byte_key = key.encode() if isinstance(key, str) else key
    byte_message = message.encode() if isinstance(message, str) else message

    # Create a new HMAC object using MD5 hash function
    hmac_md5 = hmac.new(byte_key, byte_message, hashlib.md5)

    # Return the HMAC in hexadecimal format
    return hmac_md5.hexdigest()


def calc_chcksum(context: dict[str, str], alphabet) -> None:
    """
    Calculate the checksum for authentication.

    This function updates the context dictionary with calculated info, checksum,
    and hashed password.
    """
    # Extract necessary information from context
    token = context["challenge"]
    username = context["username"]
    passwd_plain = context["password"]
    client_ip = context["client_ip"]
    ac_id = "1"
    magic_n = "200"
    magic_type = "1"

    # Calculate hashed password
    passwd_md5 = calculate_hmac_md5(token, passwd_plain)
    info(f"Password MD5: {passwd_md5}")

    # Calculate additional info
    _info = calc_info(
        {
            "username": username,
            "password": passwd_plain,
            "ip": client_ip,
            "acid": ac_id,
            "enc_ver": "srun_bx1",
        },
        token,
        alphabet,
    )
    info(f"Info: {_info}")

    # Compose and calculate the final checksum
    contents = ["", username, passwd_md5, ac_id, client_ip, magic_n, magic_type, _info]
    chkstr = token.join(contents)
    checksum = hashlib.sha1(chkstr.encode()).hexdigest()
    info(f"Checksum: {checksum}")

    # Update context with calculated values
    context["info"] = _info
    context["chksum"] = checksum
    context["password"] = f"{{MD5}}{passwd_md5}"


def calc_info(msg: dict, token: str, alpha: str = ''):
    str_msg = json.dumps(msg, separators=(",", ":"))
    info(f"str_msg: {str_msg}")
    raw_str = xEncode(str_msg, token)
    info(f"raw_str: {raw_str}")
    encoded_string = jq_b64(raw_str, alpha)
    return f"{{SRBX1}}{encoded_string}"


def byte2arr(msg: str, flag: bool) -> list[int]:
    """Corresponds to `s()` in source code"""
    mb = bytearray(msg, "utf-8")
    origin_len = len(mb)
    result = [int.from_bytes(mb[i : i + 4], "little") for i in range(0, len(mb), 4)]
    if flag:
        result.append(origin_len)
    return result


def arr2byte(a: list[int], b: bool) -> bytearray:
    """Corresponds to `l()` in source code"""
    result = bytearray()
    origin_len = a[-1] if b else len(a) * 4
    a = a[:-1] if b else a
    for i in range(len(a)):
        result.extend(a[i].to_bytes(min(4, origin_len - i * 4), "little"))
    return result


def xEncode(msg: str, key: str) -> bytearray:
    """
    🧐 honestly, I don't see what it is
    """
    if not len(msg):
        return ""
    v = byte2arr(msg, True)
    k = byte2arr(key, False)
    if len(k) < 4:
        k = k + [0] * (4 - len(k))
    n = len(v) - 1
    z = v[n]
    y = v[0]
    ff = 0xFFFFFFFF
    c = 0x9E3779B9
    m = 0
    e = 0
    p = 0
    q = 6 + 52 // (n + 1)
    d = 0
    while 0 < q:
        d = d + c & ff
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = v[p + 1]
            m = z >> 5 ^ y << 2
            m += (y >> 3 ^ z << 4) ^ (d ^ y)
            m += k[(p & 3) ^ e] ^ z
            v[p] = v[p] + m & ff
            z = v[p]
            p += 1
        y = v[0]
        m = z >> 5 ^ y << 2
        m += (y >> 3 ^ z << 4) ^ (d ^ y)
        m += k[(p & 3) ^ e] ^ z
        v[n] = v[n] + m & ff
        z = v[n]
        q -= 1
    return arr2byte(v, False)


def meet_challenge(context: dict[str, str], coll: College) -> str:
    calc_chcksum(context, coll.alpha)

    # Prepare URL parameters
    params = {
        "callback": context["prefix"],
        "action": "login",
        "username": context["username"],
        "password": context["password"],
        "ac_id": "1",
        "ip": context["client_ip"],
        "chksum": context["chksum"],
        "info": context["info"],
        "n": "200",
        "type": "1",
        "os": "Linux",
        "name": "Linux",
        "double_stack": "0",
        "_": int(time.time() * 1000),
    }

    # Construct URL
    base_url = f"{coll.host}/cgi-bin/srun_portal"
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    info(f"final url: {url}")
    return url


def login(url: str):
    response = requests.get(url)
    info(response.text)


def jq_b64(msg: bytearray, alpha: str=''):
    """
    The algorithm of jQuery failed to consider unicode
    leading to a wrong result, so we have to calculate this
    bad result
    """
    stupid_alphabet = (
        alpha
        if alpha
        else "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    result = ""
    for i in range(0, len(msg), 3):
        a = msg[i]
        b = msg[i + 1] if i + 1 < len(msg) else 0
        c = msg[i + 2] if i + 2 < len(msg) else 0
        result += stupid_alphabet[(a >> 2) & 0x3F]
        result += stupid_alphabet[(((a & 3) << 4) | (b >> 4)) & 0x3F]
        result += stupid_alphabet[(((b & 15) << 2) | (c >> 6)) & 0x3F]
        result += stupid_alphabet[c & 63]
    padding = len(msg) % 3
    if padding == 1:
        result = result[:-2] + "=="
    elif padding == 2:
        result = result[:-1] + "="
    return result


if __name__ == "__main__":
    # decomment to trace
    # basicConfig(level=INFO)
    user, coll = read_config()
    ctx = get_challenge(user.name, user.password, coll)
    url = meet_challenge(ctx, coll)
    login(url)
