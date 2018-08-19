# coding=utf-8
# author:wolf
import urllib2
from config import is_port_open, is_http


# @is_port_open
def verify(host, port=80, name=10, timeout=10, types='ip'):
    if types == 'ip':
        url = "http://%s:%d" % (host, int(port))
    else:
        url = 'http://{}'.format(host)

    error_i = 0
    flag_list = ['<th>Resin home:</th>', 'The Resin version', 'Resin Summary']
    user_list = ['admin']
    PASSWORD_DIC = ['admin', 'redsiadmin', '123456', 'admin123', '1q2w3e4r', '1234qwer']
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())

    info = {
        "url": url,
        "vuln_name": "resin weak password",
        "severity": "high",
        "proof": ""
    }
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                PostStr = 'j_username=%s&j_password=%s' % (user, password)
                res = opener.open(url + '/resin-admin/j_security_check?j_uri=index.php', PostStr ,timeout=timeout)
                res_html = res.read()
                res_code = res.code
            except urllib2.HTTPError, e:
                return
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3:
                    return
                continue
            except Exception as e:
                return 
            for flag in flag_list:
                if flag in res_html or int(res_code) == 408:
                    # info = u'%s/resin-admin 存在弱口令 用户名：%s，密码：%s' % (url, user, password)
                    info["proof"] = "username={}&password={}".format(user, password)
                    info['url'] = url + '/resin-admin'
                    return info
