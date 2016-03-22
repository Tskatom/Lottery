#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Wei Wang"
__email__ = "tskatom@vt.edu"

import sys
import os
import argparse
import pandas as pds


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--buyfile', type=str, default='./issues/buy_record.csv')
    ap.add_argument('--detail', type=str, default='./issues/detail.csv')
    return ap.parse_args()

def evaluate(buyfile, detail_file):
    with open(buyfile) as bf,  open(detail_file, 'w') as det:
        lines = bf.readlines()
        pairs = zip(lines, lines[1:])
        # detail file format
        # issueid, number, win_flag, profit, buy_detail1, buy_detail2, month,
        # day
        det.write("期数\t当期号码\t选号\t码信息\t中奖标记\t开奖号码\t支出\t盈利\t策略1\t策略2\t策略3\t倍数\t月份\t日期\n")
        for buy, target in pairs:
            buy_info = buy.strip().split('\t')
            if buy_info[4] == '------':
                continue # no buy

            times_txt = buy_info[4].split("|")[1]
            strategy = buy_info[4].split("|")[0]
            stra_detail = strategy.split("_")
            if len(stra_detail) == 1:
                stra_detail.insert(0, "1不中后")
                stra_detail.append(stra_detail[-1])
            elif len(stra_detail) == 2:
                stra_detail.append("4-" + stra_detail[1][-1])
                
            times = int(times_txt.decode('utf-8')[:-1])

            tens, units = map(len, buy_info[5].split(","))
            cost = tens * units * 2 * times
           
            """
            win_flag = True if target.strip().split("\t")[2] == "o" else False
            """
            target_shiwei = target.strip().split("\t")[1][-2]
            target_gewei = target.strip().split("\t")[1][-1]
            buy_shiwei = buy_info[5].split(",")[0]
            buy_gewei = buy_info[5].split(",")[1]
            
            if target_shiwei in buy_shiwei and target_gewei in buy_gewei:
                win_flag = True
            else:
                win_flag = False

            win_mark = 1 if win_flag else 0

            reward = 2 * times * 90 if win_flag else 0

            profit = reward - cost
            
            day = "20"+buy_info[0][:6]
            month = "20"+buy_info[0][:2]+"-"+buy_info[0][2:4]
            issue_id= buy_info[0]
            match_flag = buy_info[2]
            numbers = buy_info[1]
            choosed = buy_info[5]
            codes = buy_info[6]
            target_num = target.strip().split("\t")[1]
            # write to detail csv file
            detail_line = "%s\t%s\t%s\t%s\t%s\t%s\t%f\t%f\t%s\t%s\t%s\t%s\t%s\t%s\n" % (issue_id,
                    numbers, choosed, codes, win_mark, target_num, cost, profit, stra_detail[0],
                    stra_detail[1], stra_detail[2], times_txt, month, day)


            det.write(detail_line)
        
    # compute the summary information
    


def main():
    args = parse_args()
    buyfile = args.buyfile
    detail = args.detail

    evaluate(buyfile, detail)

if __name__ == "__main__":
    main()
