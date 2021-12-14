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
            "winlog.event_id": "4728"
          }
        }

      ], }}, }


def init():
    config = Configuration.readconfig()
    connection = str(config["elasticsearch"]["connection"])
    es = Elasticsearch([connection], verify_certs=False, ssl_show_warn=False)
    res = es.search(index=local_config["index"], body=search_query, size=local_config["max_results"])
    # Iterate through elasticsearch results
    for doc in res.get('hits', {}).get('hits'):
        member = doc.get('_source', {}).get('user', {}).get('target', {}).get('name')
        subject = doc.get('_source', {}).get('user', {}).get('name')
        group = doc.get('_source', {}).get('user', {}).get('target', {}).get('group', {}).get('name')
        Send_Alert.send(str(subject) + " added " + str(member) + " to the " + str(group), local_config["severity"])
