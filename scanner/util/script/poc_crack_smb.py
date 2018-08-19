#coding:utf-8
from smb.SMBConnection import SMBConnection
import socket
from config import is_port_open


def ip2hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        pass
    try:
        query_data = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41" + \
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" + \
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        dport = 137
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.sendto(query_data, (ip, dport))
        x = _s.recvfrom(1024)
        tmp = x[0][57:]
        hostname = tmp.split("\x00", 2)[0].strip()
        hostname = hostname.split()[0]
        return hostname
    except:
        pass


# @is_port_open
def verify(ip,port=445, name="", timeout=10, types='ip'):
    if types != 'ip':
        return
    
    if name.find('smb') == -1:
        return
    socket.setdefaulttimeout(timeout)
    user_list = ['administrator']
    hostname = ip2hostname(ip)
    PASSWORD_DIC = ['smb', 'administrators', 'admins', '123456', '1234qwer', '1q2w3e4r']
    PASSWORD_DIC.insert(0,'anonymous')
    info = {
        "url": "smb://{}:{}".format(ip, port),
        "vuln_name": "smb weak password",
        "severity": "high",
    }
    if not hostname:return
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            try:
                pass_ = str(pass_.replace('{user}', user))
                conn = SMBConnection(user,pass_,'xunfeng',hostname)
                if conn.connect(ip) == True:
                    info["proof"] = "username={}&password={}".format(user, pass_)
                    return info
            except Exception,e:
                if "Errno 10061" in str(e) or "timed out" in str(e): return
