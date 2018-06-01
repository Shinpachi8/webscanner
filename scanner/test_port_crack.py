#!/usr/bin/env python
# coding=utf-8

import re
import random
import string
import logging
from os import system
from os import path
# from commons import logger



def LogUtil(path='/tmp/portcrack.log', name='test'):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    #create formatter
    formatter = logging.Formatter(fmt=u'[%(asctime)s] [%(levelname)s] [%(funcName)s] %(message)s ')

    # create console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # create file
    file_handler = logging.FileHandler(path, encoding='utf-8')
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


logger = LogUtil()


class PortCrack(object):
    def __init__(self, port=None, ip=None, service=None):
        self.port = port
        self.service = service
        self.ip = ip
        self.username = 'username.txt'
        self.password = 'password.txt'
        self.vul_list = []

    def get_path(self):
        here = path.split(path.abspath(__file__))[0]
        return here

    def randStr(self, length=8):
        allchar = string.lowercase + string.uppercase + string.digits
        return ''.join(random.sample(allchar, length))

    def work(self):
        if self.ip is None or self.port is None or self.service is None:
            return
        cmd = 'hydra -L {uname} -P {passwd} -t 4 -s {port}  -f -o {resultfile} {server} {service} >/dev/null 2>&1'
        here = self.get_path()
        uname = path.join(here, 'util/' ,self.username)
        passwd = path.join(here, 'util/',self.password)
        resultfile = '/tmp/{}.txt'.format(self.randStr())

        r_cmd = cmd.format(uname=uname,
                        passwd=passwd,
                        port=self.port,
                        resultfile=resultfile,
                        server=self.ip,
                        service=self.service
                        )
        logger.info('cmd={}'.format(r_cmd))
        code = system(r_cmd)
        self.parse_result_hydra(code, resultfile)

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
                    msg = '{service}://{uname}:{passwd}@{ip}:{port}'
                    self.vul_list.append(msg.format(
                        service=self.service,
                        uname=username,
                        passwd=password,
                        ip=self.ip,
                        port=self.port))
                    # self.push_vul(username, password, line)
            # return len(self.vul_list)
        except Exception as e:
            logger.error('[PortCrackBase][parse_result_hydra] Exception %s' % e)



if __name__ == '__main__':
    a = PortCrack(port=3306, service='mysql',ip='127.0.0.1')
    a.work()
    print a.vul_list