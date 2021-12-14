#!/usr/bin/env python
import datetime
import re
from elasticsearch import Elasticsearch
from jobs.lib import Configuration
from jobs.lib import Send_Alert


def process_event(doc):
    process = doc.get('_source', {}).get('process', {}).get('name')
    computer = doc.get('_source', {}).get('host', {}).get('name')

    regex_list = [
            r"^tor.exe",
            r"nmap",
            r"mimikatz",
            r"psexec",
            r"adfind",
            r"pwdump",
            r"creddump",
            r"nltest",
            r"ntdsutil",
            r"procdump"
            ]

    for item in regex_list:
        a1 = re.search(item, process, re.IGNORECASE)
        if a1:
            Send_Alert.send("Suspicious process " + str(process) + " on " + str(computer), "medium")
            break


local_config = {
    "minutes": 5,
    "index": ["servers-*", "workstations-*"],
    "max_results": 1000
        }

# Query goes here
search_query = {
  "query": {
    "bool": {
      "must": [],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "format": "strict_date_optional_time",
              "gte": datetime.datetime.utcnow() - datetime.timedelta(minutes=local_config["minutes"]),
              "lte": datetime.datetime.utcnow()
            }
          }
        },
        {
          "match_phrase": {
            "winlog.channel": "Microsoft-Windows-Sysmon/Operational"
          }
        },
        {
          "match_phrase": {
            "winlog.event_id": "1"
          }
        }

      ], }}, }


def init():
    config = Configuration.readconfig()
    connection = str(config["elasticsearch"]["connection"])
    es = Elasticsearch([connection], verify_certs=False, ssl_show_warn=False)
    res = es.search(index=local_config["index"], body=search_query, size=local_config["max_results"])
    for doc in res.get('hits', {}).get('hits'):
        process_event(doc)
