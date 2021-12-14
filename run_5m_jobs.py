#!/usr/bin/env python
import threading
# Import the jobs
from jobs import SuspiciousProcess
from jobs import SuspiciousCommandline
from jobs import GroupMemberAdded 
from jobs import LockedADAccount 
from jobs import PowershellFileWrite


def thread1():
    SuspiciousProcess.init()
    SuspiciousCommandline.init()


def thread2():
    GroupMemberAdded.init()
    LockedADAccount.init()
    PowershellFileWrite.init()


if __name__ == '__main__':
    t1 = threading.Thread(target=thread1)
    t2 = threading.Thread(target=thread2)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
