#!/usr/bin/env python
import configparser

def readconfig():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config
