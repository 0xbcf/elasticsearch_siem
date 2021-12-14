#!/usr/bin/env python
import requests
from jobs.lib import Configuration


def send(msg, level):
    data = {'text': msg}
    config = Configuration.readconfig()
    if level:
        r = requests.post(str(config["alerts"][level]), json=data)
    else:
        r = requests.post(str(config["alerts"]["low"]), json=data)
