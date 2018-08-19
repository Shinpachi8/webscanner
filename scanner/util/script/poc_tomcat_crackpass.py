# coding:utf-8
# author:wolf
import urllib2
import base64
from config import is_port_open, is_http


# @is_port_open
def verify(ip, port=80, name='', timeout=10, types='ip'):

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip

    error_i = 0
    flag_list = ['/manager/html/reload', 'Tomcat Web Application Manager']
    user_list = ['admin', 'manager', 'tomcat', 'apache', 'root']
    PASSWORD_DIC = ['admin', 'manager', 'tomcat', 'apache', 'root']
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            try:
                pass_ = str(pass_.replace('{user}', user))
                login_url = 'http://' + url + '/manager/html'
                request = urllib2.Request(login_url)
                auth_str_temp = user + ':' + pass_
                auth_str = base64.b64encode(auth_str_temp)
                request.add_header('Authorization', 'Basic ' + auth_str)
                res = urllib2.urlopen(request, timeout=timeout)
                res_code = res.code
                res_html = res.read()
            except urllib2.HTTPError, e:
                res_code = e.code
                res_html = e.read()
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3: return
                continue
            except Exception as e:
                return
            if int(res_code) == 404: return
            if int(res_code) == 401 or int(res_code) == 403: continue
            for flag in flag_list:
                if flag in res_html:
                    info = {
                        "url": login_url,
                        "vuln_name": "tomcat weak password",
                        "severity": "high",
                        "proof": "username={}&password={}".format(user, pass_)
                    }
                    return info
