# coding:utf-8
import urllib2
import base64
from config import is_port_open, is_http


# @is_port_open
def verify(ip, port=80, name=None, timeout=10, types='ip'):
    info = {
        "url" : "http://{}:{}".format(ip, port),
        "vuln_name" : "weak password",
        "severity" : "high",
        "proof" : "user={}&password={}"
    }

    error_i = 0
    flag_list = ['>true</']
    user_list = ['admin']
    PASSWORD_DIC = ['admin', '123456', '12345', 'admin123']
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                if types == 'ip':
                    login_url = 'http://' + ip + ":" + str(port) + '/ISAPI/Security/userCheck'
                else:
                    login_url = 'http://{}/ISAPI/Security/userCheck'.format(ip)

                request = urllib2.Request(login_url)
                auth_str_temp = user + ':' + password
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
            if int(res_code) == 404 or int(res_code) == 403: return
            if int(res_code) == 401: continue
            for flag in flag_list:
                if flag in res_html:
                    info["proof"] = info["proof"].format(user, password)
                    return info
