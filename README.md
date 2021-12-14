# elasticsearch monitoring with python
Use to analyze elasticsearch data for security violations.


## Setup Guide
1. Clone the repository
2. Add the run_* scripts to /etc/crontab with their respective run times. eg run_10m_jobs runs every 10 minutes

```
*/5 * * * * [user] /[path]/run_5m_jobs.py >> /[path]/errors.log 2>&1
*/10 * * * * [user] /[path]/run_10m_jobs.py >> /[path]/errors.log 2>&1
*/30 * * * * [user] /[path]/run_30m_jobs.py >> /[path]/errors.log 2>&1
```
3. Modify the run scripts to run jobs