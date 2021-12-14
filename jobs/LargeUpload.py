#!/usr/bin/env python
import datetime
from elasticsearch import Elasticsearch
from jobs.lib import Configuration
from jobs.lib import Send_Alert


def format_bytes(size):
    power = 2**10
    n = 0
    power_labels = {0: '', 1: 'kilo', 2: 'mega', 3: 'giga', 4: 'tera'}
    while size > power:
        size /= power
        n += 1
    return size, power_labels[n] + 'bytes'


def process_event(doc):
    source = doc.get('_source', {}).get('source', {}).get('ip')
    destination = doc.get('_source', {}).get('destination', {}).get('ip')
    port = doc.get('_source', {}).get('destination', {}).get('port')
    sbytes = doc.get('_source', {}).get('source', {}).get('bytes')
    pretty_bytes = format_bytes(sbytes)
    if "mega" in str(pretty_bytes[1]):
        Send_Alert.send("Large upload of " + str(pretty_bytes[0]) + " " +
                        str(pretty_bytes[1]) + " from " + str(source) +
                        " to " + str(destination) + " on port " + str(port), local_config["severity"])
    else:
        # Override severity for larger uploads
        Send_Alert.send("Large upload of " + str(pretty_bytes[0]) + " " +
                        str(pretty_bytes[1]) + " from " + str(source) +
                        " to " + str(destination) + " on port " + str(port), "medium")


local_config = {
    "minutes": 10,
    "index": "netflow-*",
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
          "exists": {
            "field": "source.bytes"
          }
        }
      ],
      "must_not": [
        {
          "range": {
            "source.bytes": {
              "lt": 500000000,
              "gte": 0
            }
          }
        },
        {
          "match_phrase": {
            "destination.ip": "8.8.8.8"
          }
        },
        {
          "match_phrase": {
            "destination.ip": "8.8.8.7"
          }
        },
        {
          "match_phrase": {
            "destination.port": 1234
          }
        },
        {
          "match_phrase": {
            "destination.ip": "8.8.8.6"
          }
        }
      ],
      "should": []
    }
  }}


def init():
    config = Configuration.readconfig()
    connection = str(config["elasticsearch"]["connection"])
    es = Elasticsearch([connection], verify_certs=False, ssl_show_warn=False)
    res = es.search(index=local_config["index"], body=search_query, size=local_config["max_results"])
    for doc in res.get('hits', {}).get('hits'):
        process_event(doc)
