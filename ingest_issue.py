#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Wei Wang"
__email__ = "tskatom@vt.edu"

import sys
import os
import logging
import pytz
from datetime import datetime, timedelta
import time
import urllib2
import xlrd
import zmq

port = "5918"
if len(sys.argv) > 1:
    port = sys.argv[1]

def download(url):
    excel = urllib2.urlopen(url).read()
    wb = xlrd.open_workbook(file_contents=excel)
    sb = wb.sheet_by_index(0)
    issues = []
    for i in range(1, sb.nrows):
        issue = sb.row_values(i)
        issues.append(issue)
    return issues

def run():
    # initiate zmq
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind("tcp://*:%s" % port)

    tz = pytz.timezone(pytz.country_timezones('cn')[0])
    logging.basicConfig(filename='./log/ingest_issue.log', level=logging.INFO)
    now = datetime.now(tz).isoformat()
    logging.info('Start Ingesting %s' % now)
    url_format = "http://trend.caipiao.163.com/downloadTrendAwardNumber.html?gameEn=ssc&beginPeriod=%s&endPeriod=%s"
    while True:
        # check the website every 30 seconds
        # get the latest issue
        try:
            with open('./issues/issues.csv', 'a+') as issue_file:
                lines = [l.strip() for l in issue_file]
                latest = lines[-1].split('|')[0]
                now = datetime.now(tz)
                next_day = now + timedelta(days=1)
                end_issue = "%s120" % next_day.strftime('%y%m%d')
                url = url_format % (latest, end_issue)

                download_issues = download(url)
                # check for update
                d_latest = download_issues[-1][0]
                if d_latest == latest:
                    message = "Ingest Issues at [%s], not updated yet!" % now.isoformat()
                else:
                    # write to issues.csv
                    for issue in download_issues:
                        if issue[0] > latest:
                            socket.send_string("%s\n" % '|'.join(issue))
                            issue_file.write("%s\n" % '|'.join(issue))
                    message = "Ingest Issues at [%s], issue no[%s]" % (now.isoformat(), issue[0])
            
                logging.info(message)

                time.sleep(30)
        except KeyboardInterrupt:
            now = datetime.now(tz)
            message = "CTRL-C to quit the program at [%s]" % now.isoformat()
            logging.info(message)
            break
        except Exception as e:
            error_message = sys.exc_info()[0]
            logging.info(e)

if __name__ == "__main__":
    run()
