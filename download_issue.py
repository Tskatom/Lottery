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
import calendar


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
    now = datetime.now(tz).isoformat()
    logging.info('Start Ingesting %s' % now)
    url_format = "http://trend.caipiao.163.com/downloadTrendAwardNumber.html?gameEn=ssc&beginPeriod=%s&endPeriod=%s"
    with open('./issues/issues_2.csv', 'w') as issue_file:
        now = datetime.now(tz)
        next_day = now + timedelta(days=1)
        end_issue = "%s120" % next_day.strftime('%y%m%d')
        url = url_format % (latest, end_issue)

        download_issues = download(url)
        for issue in download_issues:
            issue_file.write("%s\n" % '|'.join(issue))


def main():
    # get past 30 months data 
    tz = pytz.timezone(pytz.country_timezones('cn')[0])
    now = datetime.now(tz).isoformat()
    if len(sys.argv) > 1:
        months = int(sys.argv[1])
    else:
        months = 30

    current_day = datetime.now(tz)
    url_format = "http://trend.caipiao.163.com/downloadTrendAwardNumber.html?gameEn=ssc&beginPeriod=%s&endPeriod=%s"
    issues = []
    for i in range(months):
        end = "%s120" % current_day.strftime("%y%m%d")
        begin_day = current_day - timedelta(days=30)
        start = "%s001" % (begin_day.strftime("%y%m%d"))
        print "%d : From %s to %s " % (i, start, end)

        current_day = begin_day - timedelta(days=1)
        url = url_format % (start, end)
        batch = download(url)
        print 'Finish %d' % i
        issues.insert(0, batch)
    # write to file
    with open('./issues/historical_issues.csv', 'a+') as f:
        old_issues = {l.strip().split('|')[0]:1 for l in f}
        for batch in issues:
            for issue in batch:
                if issue[0] not in old_issues:
                    f.write("%s\n" % '|'.join(issue))

if __name__ == "__main__":
    main()
