#!/usr/bin/env python
# coding=utf-8
import logging
 
# referer:  http://www.jianshu.com/p/feb86c06c4f4
# create logger
logger = logging.getLogger("test")
logger.setLevel(logging.INFO)
 
# create handler
filehandler = logging.FileHandler("logtest.log", mode="w", encoding="utf-8", delay=False)
streamhandler = logging.StreamHandler()
 
 
# create format
formatter = logging.Formatter("[%(asctime)s] [%(filename)s] [%(lineno)d] %(message)s")
 
# add formatter to handler
filehandler.setFormatter(formatter)
streamhandler.setFormatter(formatter)
 
# set hander to logger
logger.addHandler(filehandler) 
logger.addHandler(streamhandler)

MASSCAN_THEAD_NUM = 3
MASSCAN_LOC = "/usr/bin/"

TARGET_PORTS = '1-65535'
DEBUG = True