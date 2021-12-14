#!/usr/bin/env python
import threading
# Import the jobs
from jobs import LargeUpload


def thread1():
    LargeUpload.init()


# def thread2():
#    continue

if __name__ == '__main__':
    t1 = threading.Thread(target=thread1)
    # t2 = threading.Thread(target=thread2)
    t1.start()
    # t2.start()
    t1.join()
    # t2.join()
