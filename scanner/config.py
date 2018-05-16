#!/usr/bin/env python
# coding=utf-8
import logging
 
# referer:  http://www.jianshu.com/p/feb86c06c4f4
# create logger


MASSCAN_THEAD_NUM = 3
MASSCAN_LOC = "/usr/bin/"
MASSCAN_LOC_WIN = 'c:\\Program Files\\masscan\\'

TARGET_PORTS = '1-65535'
DEBUG = True

DB_HOST = '127.0.0.1'
DB_PORT = '3306'
DB_DATABASE = 'scan'