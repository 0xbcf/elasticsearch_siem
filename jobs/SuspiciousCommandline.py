#!/usr/bin/env python
import datetime
import re
from elasticsearch import Elasticsearch
from jobs.lib import Configuration
from jobs.lib import Send_Alert


def process_event(doc):
    commandline = doc.get('_source', {}).get('process', {}).get('command_line')
    computer = doc.get('_source', {}).get('host', {}).get('name')

    regex_list = [
            r"powershell\.exe.*\-encod",
            r"domain admins",
            r"invoke\-dcsync",
            r"invoke\-bypassuac",
            r"javascript:eval",
            r"enterprise admins",
            r"invoke\-createremotethread",
            r"invoke\-mimikatz",
            r"get\-foxdump",
            r"get\-vaultcredential",
            r"get\-decryptedcpassword",
            r"delete shadows",
            r"recoveryenabled no",
            r"shadowcopy delet",
            r"secretsdump",
            r"win32_shadowcopy",
            r"wmic.*shadowcopy",
            r"recoveryenabled no",
            r"logonpasswords",
            r"uselogoncredential",
            r"sekurlsa",
            r"net\.webclient",
            r"jndi",
            r"ntds.dit"
            ]

    for item in regex_list:
        a1 = re.search(item, commandline, re.IGNORECASE)
        if a1:
            Send_Alert.send("Suspicious commandline " + str(commandline) + " on " +
                            str(computer), local_config["severity"])
            break


local_config = {
    "minutes": 5,
    "index": ["servers-*", "workstations-*"],
    "max_results": 1000,
    "severity": "medium"
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
