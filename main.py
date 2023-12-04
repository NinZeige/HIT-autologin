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


# steps:
#   1. get the challenge
#   2. meet the challenge
#   3. send the login request

def get_challenge(username: str, password: str) -> dict[str, str]:
    timestamp = int(time.time() * 1000)
    mystery_number = "112406802133408291239"
    url = (
        f"https://webportal.hit.edu.cn/cgi-bin/get_challenge?"
        f"callback=jQuery{mystery_number}_{timestamp}&username={username}&_={timestamp}"
    )

    try:
        response = requests.get(url)
        info(response.text)
    except requests.RequestException as e:
        error(f"HTTP request failed: {e}")
        return None

    response_format = re.compile(r"(jQuery\d+_\d+)\((.*)\)")
    match = response_format.match(response.text)
    if not match:
        error("Regex match failed")
        return None

    prefix = match.group(1)
    response_content = match.group(2)
    info(response_content)

    try:
        response_json = json.loads(response_content)
    except json.decoder.JSONDecodeError:
        error("JSON decode error: bad format")
        return None

    if not isinstance(response_json, dict):
        error("JSON decode error: not a dict")
        return None

    # Add more info to response
    response_json["username"] = username
    response_json["password"] = password
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


def calc_chcksum(context: dict[str, str]) -> None:
    """
    Calculate the checksum for authentication.

    This function updates the context dictionary with calculated info, checksum,
    and hashed password.
    """
    # Extract necessary information from context
    token = context["challenge"]
    username = context["username"]
    password = context["password"]
    client_ip = context["client_ip"]
    ac_id = "1"
    magic_n = "200"
    magic_type = "1"

    # Calculate hashed password
    passwd_md5 = calculate_hmac_md5(token, password)
    info(f"Password MD5: {passwd_md5}")

    # Calculate additional info
    _info = calc_info(
        {
            "username": username,
            "password": password,
            "ip": client_ip,
            "acid": ac_id,
            "enc_ver": "srun_bx1",
        },
        token,
    )
    info(f"Info: {_info}")

    # Compose and calculate the final checksum
    contents = ['', username, passwd_md5, ac_id, client_ip, magic_n, magic_type, _info]
    chkstr = token.join(contents)
    checksum = hashlib.sha1(chkstr.encode()).hexdigest()
    info(f"Checksum: {checksum}")

    # Update context with calculated values
    context["info"] = _info
    context["chksum"] = checksum
    context["password"] = f"{{MD5}}{passwd_md5}"


def calc_info(msg: dict, token: str):
    str_msg = json.dumps(msg, separators=(",", ":"))
    info(f"str_msg: {str_msg}")
    raw_str = xEncode(str_msg, token)
    info(f"raw_str: {raw_str}")
    encoded_string = jq_b64(raw_str)
    return f"{{SRBX1}}{encoded_string}"


# s and l function is inter reversible
def s(msg: str, flag: bool) -> str:
    origin_len = len(msg)
    msg = bytearray(msg, "utf-8")
    # padding to 4 bytes
    while len(msg) % 4 != 0:
        msg.append(0)
    result = [0] * ((len(msg) >> 2))
    for i in range(0, origin_len, 4):
        result[i >> 2] = msg[i] | msg[i + 1] << 8 | msg[i + 2] << 16 | msg[i + 3] << 24
    if flag:
        result.append(origin_len)
    return result


def l(a: list[int], b: bool) -> str:
    result = []
    c = (len(a) - 1) * 4
    if b:
        m = a[-1]
        if m > c or m < c - 3:
            return None
        c = m

    for i in range(len(a)):
        result.append(a[i] & 0xFF)
        result.append(a[i] >> 8 & 0xFF)
        result.append(a[i] >> 16 & 0xFF)
        result.append(a[i] >> 24 & 0xFF)
    if b:
        result = result[0:c]
    return [chr(element) for element in result]


def xEncode(msg: str, key: str) -> bytearray:
    """
    🧐 honestly, I don't see what it is
    """
    if not len(msg):
        return ""
    v = s(msg, True)
    k = s(key, False)
    if len(k) < 4:
        k = k + [0] * (4 - len(k))
    n = len(v) - 1
    z = v[n]
    y = v[0]
    ff = 0xffffffff
    c = 0x9e3779b9
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
    return l(v, False)


def meet_challenge(context: dict[str, str]) -> str:
    calc_chcksum(context)

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
    base_url = "https://webportal.hit.edu.cn/cgi-bin/srun_portal"
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    info(f"final url: {url}")
    return url


def login(url: str):
    response = requests.get(url)
    info(response.text)


def jq_b64(msg: str):
    """
    the algorithm of jQuery failed to consider unicode
    leading to a wrong result, so we have to calculate this
    bad result
    """
    stupid_alphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
    result = ""
    x = []
    for element in msg:
        x.append(ord(element))
    for i in range(0, len(x), 3):
        a = x[i]
        b = x[i + 1] if i + 1 < len(x) else 0
        c = x[i + 2] if i + 2 < len(x) else 0
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
    username = "输入学号加创新学分"
    password = "won't tell you :)"
    # decomment to trace
    # basicConfig(level=INFO)
    ctx = get_challenge(username, password)
    url = meet_challenge(ctx)
    login(url)
