#!/usr/bin/env python
import datetime
from elasticsearch import Elasticsearch
from jobs.lib import Configuration
from jobs.lib import Send_Alert


local_config = {
    "minutes": 30,
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
            "winlog.event_id": "4625"
          }
        },
        {
          "match_phrase": {
            "winlog.logon.failure.reason": "Unknown user name or bad password."
          }
        }

      ],}},}


def init():
    config = Configuration.readconfig()
    connection = str(config["elasticsearch"]["connection"])
    es = Elasticsearch([connection], verify_certs=False, ssl_show_warn=False)
    res = es.search(index=local_config["index"], body=search_query, size=local_config["max_results"])

    failed_logon = {}
    # Iterate through results
    for doc in res.get('hits', {}).get('hits'):
        username = doc.get('_source', {}).get('winlog', {}).get('event_data', {}).get('TargetUserName')
        ip = doc.get('_source', {}).get('related', {}).get('ip')
        if not ip:
            ip = "na"
        if not username:
            username = "na"

        if username not in failed_logon:
            if ip:
                failed_logon[username] = {'count': 1, 'ip': [str(ip)]}
            else:
                failed_logon[username] = {'count': 1, 'ip': ['na']}
        else:
            count=failed_logon[username]['count'] + 1
            iplist = failed_logon.get(username, {}).get("ip")
            failed_logon[username] = {"count": count, "ip": iplist}
            if ip and iplist:
                if str(ip) in iplist:
                    continue
                else:
                    iplist.append(str(ip))
                    failed_logon[username]["ip"] = iplist
    for item in failed_logon:
        if failed_logon[item]['count'] < 15:
            continue
        Send_Alert.send(item + " failed to logon to AD " +
                        str(failed_logon[item]['count']) + " times from " +
                        str(len(failed_logon[item]["ip"])) + " location(s)", local_config["severity"])
