#!/usr/bin/env python
#coding=utf-8

import multiprocessing
import time


def func(a, b):
    print a
    print b
    print a+b
    time.sleep(10)

def runFunc(func, *args):
    print args
    p = multiprocessing.Process(target=func, args=args)
    p.daemon = True
    p.start()
    starttime = time.time()
    while True:
        if time.time() - starttime > 7:
            break
        else:
            time.sleep(10)
    print "done"


if __name__ == '__main__':
    runFunc(func, 1, 2)
