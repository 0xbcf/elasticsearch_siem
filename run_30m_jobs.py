#!/usr/bin/env python
import threading
# Import the jobs
from jobs import FailedADLogin
from jobs import EventLogClear
from jobs import LocalAccountCreated


def thread1():
    FailedADLogin.init()
    EventLogClear.init()
    return


def thread2():
    LocalAccountCreated.init()
    return


if __name__ == '__main__':
    t1 = threading.Thread(target=thread1)
    t2 = threading.Thread(target=thread2)
    t1.start()
    t2.start()
    t1.join()
    t2.join()