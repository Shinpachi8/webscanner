#!/usr/bin/env python
# coding=utf-8
import urllib2
import re
import base64
from config import is_port_open, is_http


def request(url, user="", password=""):
    data = """<?xml version="1.0"?>
    <methodCall>
    <methodName>supervisor.getSupervisorVersion</methodName>
    </methodCall>
    """
    req = urllib2.Request(url, data)
    if user != "" or password != "":
        basic = base64.b64encode("%s:%s" % (user, password))
        req.add_header(
            'Authorization', 'Basic %s' % basic)
    try:
        resp = urllib2.urlopen(req)
        if resp:
            respdata = resp.read()
            return respdata
    except:
        pass
    return None


def check_unauth(url):
    resp = request(url)
    if resp is not None and "<methodResponse>" in resp:
        return ("存在未授权访问漏洞", resp)
    return (None, resp)


# @is_port_open
def verify(ip, port=9001, name='', timeout=10, types='ip'):

    user_list = ['user', 'admin', 'manager', 'root']
    PASSWORD_DIC = ['admin', 'user', 'manager', 'root', '{user}123']
    if types == 'ip':
        url = "http://" + ip + ":" + str(port) + "/RPC2"
    else:
        url = 'http://' + ip + '/RPC2'
    retinfo = ""
    info = {
        "url": url,
        "vuln_name": "supervisor weak password, cve-2017-11610",
        "severity": "high",
        "proof": ""
    }
    info1, resp = check_unauth(url)
    if info1 is None:
        for user in user_list:
            for pass_ in PASSWORD_DIC:
                pass_ = str(pass_.replace('{user}', user))
                resp = request(url, user=user, password=pass_)
                if resp is None:
                    continue
                elif "<methodResponse>" in resp:
                    retinfo += "username=%s&password=%s" % (user, pass_)
                    retinfo += "&version=%s" % checkversion(resp)
                    info["proof"] = retinfo
                    return info
    else:
        retinfo = info1
        retinfo += "&version=%s" % checkversion(resp)
        info["proof"] = retinfo
    return info


def checkversion(respdata):
    info = "存在远程代码执行漏洞 CVE-2017-11610"
    m = re.search('<string>(\d+?\.\d+?\.\d+?)</string>', respdata)
    if m:
        version = m.group(1)
    else:
        return ""
    if vc(version, "3.0.0") == '<':
        return ""
    if vc(version, "3.3.3") == "<" and vc(version, "3.3.0") != "<":
        return info
    if vc(version, "3.2.4") == "<" and vc(version, "3.2.0") != "<":
        return info
    if vc(version, "3.1.4") == "<" and vc(version, "3.1.0") != "<":
        return info
    if vc(version, "3.0.1") == "<" and vc(version, "3.0.0") != "<":
        return info


def vc(v1, v2):
    d1 = re.split('\.', v1)
    d2 = re.split('\.', v2)
    d1 = [int(d1[i]) for i in range(len(d1))]
    d2 = [int(d2[i]) for i in range(len(d2))]
    if(d1 > d2):
        return '>'
    if(d1 < d2):
        return '<'
    if(d1 == d2):
        return '='

if __name__ == '__main__':
    print 'test'
