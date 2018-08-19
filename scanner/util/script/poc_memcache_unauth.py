# coding:utf-8
import socket
from config import is_port_open


# @is_port_open
def verify(ip, port=11211, name="", timeout=10, types='ip'):
    info = {
        "url": "memcache://{}:{}".format(ip, port),
        "vuln_name": "unauth",
        "severity": "medium",
    }
    try:
        if types != 'ip':
            return
        
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send("stats\r\n")
        result = s.recv(1024)
        if "STAT version" in result:
            return info
    except Exception, e:
        pass
