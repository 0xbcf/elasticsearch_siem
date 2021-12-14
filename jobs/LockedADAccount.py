#!/usr/bin/env python
import datetime
from elasticsearch import Elasticsearch
from jobs.lib import Configuration
from jobs.lib import Send_Alert


local_config = {
    "minutes": 5,
    "index": "servers-*",
    "max_results": 1000,
    "severity": "low"
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
            "winlog.channel": "Security"
          }
        },
        {
          "match_phrase": {
            "winlog.event_id": "4740"
          }
        }

      ], }}, }


def init():
    config = Configuration.readconfig()
    connection = str(config["elasticsearch"]["connection"])
    es = Elasticsearch([connection], verify_certs=False, ssl_show_warn=False)
    res = es.search(index=local_config["index"], body=search_query, size=local_config["max_results"])
    # Iterate through results
    for doc in res.get('hits', {}).get('hits'):
        username = doc.get('_source', {}).get('user', {}).get('target', {}).get('name')
        Send_Alert.send(username + " account was locked in AD", local_config["severity"])
