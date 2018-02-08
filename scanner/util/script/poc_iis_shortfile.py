# coding:utf-8
import urllib2
from config import is_port_open, is_http


@is_port_open
def verify(ip, port=80, name=None, timeout=10):
    info = {
        "url" : "http://{}:{}".format(ip, port),
        "vuln_name" : "iis shortfile",
        "severity" : "low",
    }
    if is_http(ip, int(port)) is False:
        return
    try:
        url = ip + ":" + str(port)
        flag_400 = '/otua*~1.*/.aspx'
        flag_404 = '/*~1.*/.aspx'
        request = urllib2.Request('http://' + url + flag_400)
        req = urllib2.urlopen(request, timeout=timeout)
        if int(req.code) == 400:
            req_404 = urllib2.urlopen('http://' + url + flag_404, timeout=timeout)
            if int(req_404.code) == 404:
                return info
        return False
    except Exception, e:
        return False
