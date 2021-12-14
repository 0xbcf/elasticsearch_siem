#!/usr/bin/env python
import datetime
from elasticsearch import Elasticsearch
from jobs.lib import Configuration
from jobs.lib import Send_Alert


local_config = {
    "minutes": 30,
    "index": ["workstations-*", "servers-*"],
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
            "winlog.event_id": "11"
          }
        },
        {
          "match_phrase": {
            "process.name": "powershell.exe"
          }
        }
      ],
    }
  },
}


def init():
    config = Configuration.readconfig()
    connection = str(config["elasticsearch"]["connection"])
    es = Elasticsearch([connection], verify_certs=False, ssl_show_warn=False)
    res = es.search(index=local_config["index"], body=search_query, size=local_config["max_results"])
    # Iterate through results
    for doc in res['hits']['hits']:
        if doc['_source']['file']['path'].startswith('C:\\example\\exclude_dir\\'):
            continue
        Send_Alert.send("Powershell on " + doc['_source']['host']['name'] +
                        " wrote " + doc['_source']['file']['path'], local_config["severity"])
