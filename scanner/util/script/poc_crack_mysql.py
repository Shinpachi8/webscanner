# coding:utf-8
import re
import hashlib
import struct
import binascii
import socket
from config import is_port_open




def get_hash(password, scramble):
    hash_stage1 = hashlib.sha1(password).digest()
    hash_stage2 = hashlib.sha1(hash_stage1).digest()
    to = hashlib.sha1(scramble + hash_stage2).digest()
    reply = [ord(h1) ^ ord(h3) for (h1, h3) in zip(hash_stage1, to)]
    hash = struct.pack('20B', *reply)
    return hash


def get_scramble(packet):
    tmp = packet[15:]
    m = re.findall("\x00?([\x01-\x7F]{7,})\x00", tmp)
    if len(m) > 3: del m[0]
    scramble = m[0] + m[1]
    try:
        plugin = m[2]
    except:
        plugin = ''
    return plugin, scramble


def get_auth_data(user, password, scramble, plugin):
    user_hex = binascii.b2a_hex(user)
    pass_hex = binascii.b2a_hex(get_hash(password, scramble))
    if not password:
        data = "85a23f0000000040080000000000000000000000000000000000000000000000" + user_hex + "0000"
    else:
        data = "85a23f0000000040080000000000000000000000000000000000000000000000" + user_hex + "0014" + pass_hex
    if plugin: data += binascii.b2a_hex(
        plugin) + "0055035f6f73076f737831302e380c5f636c69656e745f6e616d65086c69626d7973716c045f7069640539323330360f5f636c69656e745f76657273696f6e06352e362e3231095f706c6174666f726d067838365f3634"
    len_hex = hex(len(data) / 2).replace("0x", "")
    auth_data = len_hex + "000001" + data
    return binascii.a2b_hex(auth_data)


# @is_port_open
def verify(ip, port=3306, name='', timeout=10, types='ip'):
    if types != 'ip':
        return
    
    if int(port) != 3306 or "mysql" not in name.lower():
        return
    socket.setdefaulttimeout(timeout)
    user_list = ['root']
    PASSWORD_DIC = ['root', '123456', 'admin', '1234qwer', '1q2w3e4r']
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            try:
                pass_ = str(pass_.replace('{user}', user))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, int(port)))
                packet = sock.recv(254)
                # print packet
                plugin, scramble = get_scramble(packet)
                auth_data = get_auth_data(user, pass_, scramble, plugin)
                sock.send(auth_data)
                result = sock.recv(1024)
                if result == "\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00":
                    info = {
                        "url": "mysql://{}:{}@{}:{}".format(user, pass_, ip, port),
                        "vuln_name": "mysql weak password",
                        "severity": "high",
                        "proof": "username={}&password={}".format(user, pass_)
                    }
                    return info
            except Exception, e:
                if "Errno 10061" in str(e) or "timed out" in str(e): return
