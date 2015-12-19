#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Wei Wang"
__email__ = "tskatom@vt.edu"

import sys
import os
import zmq
import logging
import pytz
from datetime import datetime, timedelta
import argparse
import json
import smtplib
import numpy as np
import re
from dateutil import parser
from wechat_sdk import WechatExt
import config
import time

"""
Hint:
    连４中１表示连续４期或者４期以上的数字出现在落／杀／冷码后，然后出现一期不在，发送信号
"""

logging.basicConfig(filename='./log/simulation.log', level=logging.INFO)


def wechat_login():
    login_info = config.login_info
    wechat = WechatExt(**login_info)
    return wechat

def send_message(wechat, message):
    group_id = config.group_id
    max_retry = 3
    done = False
    tried = 0
    while tried < max_retry and not done:
        tried += 1
        try:
            # get user list
            users = json.loads(wechat.get_user_list(groupid=group_id))
            for u in users["contacts"]:
                uid = u["id"]
                wechat.send_message(uid, message)
            done = True
        except Exception as e:
            logging.info("retry logining to Wechat")
            logging.info(e)
            time.sleep(1)
            wechat = wechat_login()


def send_email(user, pwd, recipient, subject, body):
    gmail_user = user
    gmail_pwd = pwd
    FROM = user
    TO = recipient if type(recipient) is list else [recipient]
    SUBJECT = subject
    TEXT = body

    message = """From: %s\nTo: %s\nSubject: %s\n\n%s""" % (
            FROM, ", ".join(TO), SUBJECT, TEXT)
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(gmail_user, gmail_pwd)
        server.sendmail(FROM, TO, message)
        server.close()
        logging.info("Successfully send the mail")
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        err_msg = "Error: %s, in Line No %d" % (exc_type, exc_tb.tb_lineno)
        logging.info("Failed to send the mail: [%s]" % err_msg)

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=str, default='6000', help='the ZMQ port')
    ap.add_argument('--issue_file', type=str, default='./issues/init_issue.csv')
    return ap.parse_args()

def initiate_codes(lottery_file):
    """
    construct the missing matrix diction, the key is the round
    and the value is missing times, for inititate, we start from 
    20150901001
    """
    # load the lottery data
    lottery = {}
    with open(lottery_file) as lf:
        head = lf.readline()
        prev = None
        for line in lf:
            info = line.strip().split('|')
            issue = info[0]
            nums = map(int, info[1:])
            lottery[issue] = {"numbers": nums, "previous":prev, "issue": issue}
            prev = issue

    # get the missing info for 20150901001
    issues = sorted(lottery.keys())
    lot_miss_info = {}
    for issue in issues[100:]:
        lot_miss_info[issue] = {}
        # 0: ten thousand, 1: thousand, 2: hundred, 3: ten, 4: unit
        for i in range(5):
            lot_miss_info[issue][i] = {}
            for dig in range(10):
                lot_miss_info[issue][i][dig] = 0
                mis_count = 0
                # trace back and get the previous appearence
                cur = issue
                while True:
                    lot = lottery[cur]
                    if lot["numbers"][i] == dig:
                        break
                    else:
                        mis_count += 1
                        cur = lot["previous"]
                lot_miss_info[issue][i][dig] = mis_count
   
    # compute the codes information
    codes = {}
    for issue in issues[100:]:
        # currently we only consider unit(4) and ten(3) digit codes
        # we have defined 7 codes
        # luo_ma: 当前中奖数字
        # leng_1_ma: 当前期中最大间隔的数字
        # leng_2_ma: 当前期中第二大间隔的数字
        # sha_ma: 十位(落码-1), 个位(落码*3+3)
        # chuan_1: 落码-1
        # chuan_2: 落码+1
        # 隔码: 上一期的落码
        codes[issue] = {}
        for dig in range(3, 5):
            code = compute_code(issue, dig, lottery, lot_miss_info)
            codes[issue][dig] = code

    # compute the match information
    matched = {} # 只匹配落／杀／冷１２码
    full_matched = {}# 匹配所有６码
    match_keys = ["luo_ma", "leng_1_ma", "leng_2_ma", "sha_ma"]
    full_match_keys = match_keys + ["chuan_1", "chuan_2", "ge_ma"]
    for issue in issues[101:]:
        prev_id = lottery[issue]["previous"]
        numbers = lottery[issue]["numbers"]
        prev_code = codes[prev_id]
        flag, full_flag = update_match(lottery[issue], prev_code)
        matched[issue] = flag
        full_matched[issue] = full_flag
    
    # compute the l4z1hbz
    l4z1hbz_seq = {}
    for issue in issues[108:]:
        l4z1hbz_seq[issue] = compute_l4z1hbz(issue, matched, lottery)

    return lottery, lot_miss_info, codes, matched, full_matched, l4z1hbz_seq

def compute_code(issue_id, dig, lottery, lot_miss_info):
    lot = lottery[issue_id]
    code = {}
    code["luo_ma"] = lot["numbers"][dig]
    miss = sorted(lot_miss_info[issue_id][dig].items(), key=lambda x:x[1], reverse=True)
    code["leng_1_ma"] = miss[0][0]
    code["leng_2_ma"] = miss[1][0]
    if dig == 3:
        code["sha_ma"] = (lot["numbers"][dig] - 1) % 10
    elif dig == 4:
        code["sha_ma"] = (lot["numbers"][dig] * 3 + 3) % 10
    code["chuan_1_ma"] = (lot["numbers"][dig] - 1) % 10
    code["chuan_2_ma"] = (lot["numbers"][dig] + 1) % 10
    code["ge_ma"] = lottery[lot["previous"]]["numbers"][dig]
    return code

def update_miss(lot, prev_miss_info):
    numbers = lot["numbers"]
    miss = {}
    for dig, num in enumerate(numbers):
        miss[dig] = {}
        for i in range(10):
            if num == i:
                miss[dig][i] = 0
            else:
                miss[dig][i] = prev_miss_info[dig][i] + 1
    return miss

def update_match(lot, prev_code):
    numbers = lot["numbers"]
    flag = False
    full_flag = False
    match_keys = ["luo_ma", "leng_1_ma", "leng_2_ma", "sha_ma"]
    full_match_keys = match_keys + ["chuan_1_ma", "chuan_2_ma", "ge_ma"]
    for dig in range(3, 5):
        codes = prev_code[dig]
        for key in match_keys:
            if codes[key] == numbers[dig]:
                flag = True
        for key in full_match_keys:
            if codes[key] == numbers[dig]:
                full_flag = True
    return flag, full_flag


def run(args):
    tz = pytz.timezone(pytz.country_timezones('cn')[0])
    now = datetime.now(tz)
    logging.info('Start Scc Monitoring at [%s]' % now.isoformat())

    # load the current issue files
    issue_file = args.issue_file
    port = args.port
    lottery, lot_miss_info, codes, matched, full_matched, l4z1hbz_seq = initiate_codes(issue_file)
    # record the information
    record_file = "./issues/buy_record.csv"

    previous = sorted(lottery.keys())[-1]
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    logging.info('Start to receiving subscription from SCC ingest process')
    wechat = wechat_login()
    logging.info('Login into WeChat')
    try:
        socket.connect("tcp://localhost:%s" % port)
        socket.setsockopt(zmq.SUBSCRIBE, "")
        while True:
            data = socket.recv()
            logging.info("Received update issue[%s] at [%s]" % (data.strip(), datetime.now(tz).isoformat()))
            # update lottery information
            data_str = data.strip()
            data = data.strip().split('|')
            cur_id = data[0]
            cur_nums = map(int, data[1:])
            if cur_id <= previous:
                continue
            lottery[cur_id] = {"numbers": cur_nums, "previous": previous, "issue": cur_id}
            # update miss information
            lot_miss_info[cur_id] = update_miss(lottery[cur_id], lot_miss_info[previous])
            # update code information
            codes[cur_id] = {}
            for i in range(3, 5):
                codes[cur_id][i] = compute_code(cur_id, i, lottery, lot_miss_info)

            # update matched
            prev_code = codes[previous]
            flag, full_flag = update_match(lottery[cur_id], prev_code)
            matched[cur_id] = flag
            full_matched[cur_id] = full_flag

            # update l4z1hbz
            l4z1hbz_seq[cur_id] = compute_l4z1hbz(cur_id, matched, lottery)

            previous = cur_id

            # generate the signal
            sorted_matched = sorted(matched.items(), key=lambda x:x[0], reverse=True)
            sorted_full_matched = sorted(full_matched.items(), key=lambda x:x[0], reverse=True)

            signals = generate_signals(sorted_matched, sorted_full_matched, l4z1hbz_seq)

            # write the record

            nums = ''.join(map(str, lottery[cur_id]["numbers"]))
            m4 = 'x' if matched[cur_id] else 'o'
            m6 = 'x' if full_matched[cur_id] else 'o'
            
            full_message = "%s\t%s\t%s\t%s\t" % (cur_id, nums, m4, m6)
            normal_message = normal_template(lottery[cur_id], codes[cur_id])

            if len(signals):
                try:
                    message = template(signals, lottery[cur_id], codes[cur_id])
                    logging.info("收到信号: %s at [%s]" % (message, datetime.now(tz).isoformat()))
                    # send_message(wechat, message)
                    # check auto buy
                    buy_info = autobuy_check(signals)
                    if buy_info:
                        sig, times = buy_info
                        buy_message = buy_template(sig, times, lottery[cur_id], codes[cur_id]) 
                        full_message += buy_message
                    else:
                        full_message += normal_message
                except Exception as e:
                    err_msg = "Send Message Error %s at %s" % (e, datetime.now(tz).isoformat())
                    logging.info(err_msg)
            else:
                full_message += normal_message

            print full_message
            with open(record_file, 'a+') as record_f:
                record_f.write(full_message)

    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        err_msg = "Error: %s, in Line No %d" % (exc_type, exc_tb.tb_lineno)
        print sys.exc_info()
        logging.info(err_msg)


def autobuy_check(signals):
    # 检测自动下注信号
    buy_rules = {"1bz": 3, "2bz": 6, "3bz": 9, "l4z1all": {1: 3, 2:6, 3:9}}
    for sig in signals:
        sig_type = sig.split("|")[0]
        if sig_type in buy_rules:
            if sig_type == "l4z1all":
                buy_time = int(sig_type.split("-")[1])
                times = buy_rules[sig_type][buy_time]
            else:
                times = buy_rules[sig_type]
            return sig, times
    return None
    

def generate_signals(sorted_matched, sorted_full_matched, l4z1hbz_seq):
    signals = []
   
    """
    signal = signal_continue3_l4z1(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测连续３次连４中１后不中: [%s]" % signal)
    
    signal = signal_continue3_l3z1(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测连续３次连３中１后不中: [%s]" % signal)

    signal = signal_4day_l4z1hbz(l4z1hbz_seq)
    if signal:
        signals.append(signal)
    logging.info("检测连续４天出现连４中１后不中: [%s]" % signal)

    signal = signal_lian4zhong1(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测连４中１: [%s]" % signal)
    
    signal = signal_l4z1_after(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测连４中１后:[%s]" % signal)

    """

    signal = signal_1buzhong(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测１不中[%s]" % signal)
    
    signal = signal_2buzhong(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测２不中[%s]" % signal)
    
    signal = signal_3buzhong(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测3不中 [%s]" % signal)
    
    signal = signal_first_l4z1_all(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测连４中１全序列 [%s]" % signal)

    """
    signal = signal_q4z1_after(sorted_matched, sorted_full_matched)
    if signal:
        signals.append(signal)
    logging.info("全４中１后具体信号 [%s]" % signal)
    """

    return signals

def normal_template(cur_lot, cur_code):
    dig2name = {3: "十位", 4: "个位"}
    # issue message
    line = "------"
    code_mess = ""
    code_order = ["luo_ma", "sha_ma", "leng_1_ma", "leng_2_ma"]
    choosed = []
    for dig in sorted(dig2name.keys()):
        cs = range(10)
        for code in code_order:
            code_mess += "%d" % cur_code[dig][code]
            if cur_code[dig][code] in cs:
                cs.remove(cur_code[dig][code])
        code_mess += ","
        choosed.append("".join(map(str,cs)))

    code_mess = code_mess.strip()
    choosed_mess = ",".join(choosed)

    message = "%s\t%s\t%s\n" % (line, choosed_mess, code_mess)
    return message


def buy_template(sig, times, cur_lot, cur_code):
    sig2name = {"l4z1": "连４中１", "1bz": "１不中", "2bz": "２不中", "3bz": "３不中", "l4z1all": "连４中１后",
            "l4z1h": "连４中１后", "3l4z1":"连续３次连４中１后",  "3l3z1": "连续３次连３中１后", 
            "4day_l4z1hbz": "连续４天出现连４中１后不中", "q4z1h": "全４中１后"}
    
    code2name = {"luo_ma": "落码", "leng_1_ma": "冷１码", "leng_2_ma": "冷２码",
            "sha_ma": "杀码", "chuan_1_ma": "传１码", "chuan_2_ma":"传２码", "ge_ma": "隔码"}

    dig2name = {3: "十位", 4: "个位"}
    sig_info = sig.split("|")
    if len(sig_info) > 1:
        name = sig2name[sig_info[0]] + "_" + sig_info[1]
    else:
        name = sig2name[sig_info[0]]
    # issue message
    line = "%s|%d倍" % (name, times)
    code_mess = ""
    code_order = ["luo_ma", "sha_ma", "leng_1_ma", "leng_2_ma"]
    choosed = []
    for dig in sorted(dig2name.keys()):
        cs = range(10)
        for code in code_order:
            code_mess += "%d" % cur_code[dig][code]
            if cur_code[dig][code] in cs:
                cs.remove(cur_code[dig][code])
        code_mess += ","
        choosed.append("".join(map(str,cs)))

    code_mess = code_mess.strip()
    choosed_mess = ",".join(choosed)

    message = "%s\t%s\t%s\n" % (line, choosed_mess, code_mess)
    return message


def template(signals, cur_lot, cur_code):
    sig2name = {"l4z1": "连４中１", "1bz": "１不中", "2bz": "２不中", "3bz": "３不中", "l4z1all": "连４中１后",
            "l4z1h": "连４中１后", "3l4z1":"连续３次连４中１后",  "3l3z1": "连续３次连３中１后", 
            "4day_l4z1hbz": "连续４天出现连４中１后不中", "q4z1h": "全４中１后"}
    
    code2name = {"luo_ma": "落码", "leng_1_ma": "冷１码", "leng_2_ma": "冷２码",
            "sha_ma": "杀码", "chuan_1_ma": "传１码", "chuan_2_ma":"传２码", "ge_ma": "隔码"}

    dig2name = {3: "十位", 4: "个位"}
    # issue message
    message = "当前期数:%s, 开奖号码: %s\n" % (cur_lot["issue"], 
            "".join(map(str,cur_lot["numbers"])))

    # signal message
    for i, signal in enumerate(signals):
        sig_info = signal.split("|")
        if len(sig_info) > 1:
            name = sig2name[sig_info[0]] + "_" + sig_info[1]
        else:
            name = sig2name[sig_info[0]]
        message += "信号 %d: %s\n" % (i+1, name)

    # code message
    message += "码信息\n"
    code_order = ["luo_ma", "sha_ma", "leng_1_ma", "leng_2_ma", "ge_ma", "chuan_1_ma", "chuan_2_ma"]
    for i in range(3, 5):
        dig_name = dig2name[i]
        message += "%s: " % dig_name
        for code in code_order:
            message += "%s(%d) " % (code2name[code], cur_code[i][code])
        message += "\n"
    return message


def signal_lian4zhong1(sorted_matched):
    """连４中１信号
    输入参数：　[(期数ｔ, matched), （期数t-1, matched）．．．]
    """
    result = None
    values = [s[1] for s in sorted_matched]
    if values[0] == False:
        next_false_index = values.index(False, 1)
        if next_false_index > 4:
            result = "l4z1"
            logging.info("连４中１信号 %s " % values[:next_false_index+1])
    return result

def signal_1buzhong(sorted_matched):
    """1不中后信号"""
    result = None
    values = [s[1] for s in sorted_matched]
    value_str = ''.join(map(str, map(int, values)))
    rule = "10{1,}10"
    if re.match(rule, value_str):
        result = "1bz"
    return result

def signal_2buzhong(sorted_matched):
    """2不中后信号"""
    result = None
    values = [s[1] for s in sorted_matched]
    value_str = ''.join(map(str, map(int, values)))
    rule = "110{1,}10"
    if re.match(rule, value_str):
        result = "2bz"
    return result

def signal_3buzhong(sorted_matched):
    """3不中后信号"""
    result = None
    values = [s[1] for s in sorted_matched]
    value_str = ''.join(map(str, map(int, values)))
    rule = "1110{1,}10"
    if re.match(rule, value_str):
        result = "3bz"
    return result

def signal_first_l4z1_all(sorted_matched):
    result = None
    values = [s[1] for s in sorted_matched]
    rules = [1, 2, 3] # represent 不中1/2/3
    for num in rules:
        p2 = [True] * (num - 1) + [False]
        if np.allclose(values[:num], p2):
            # check second part rule
            last_false = values.index(False, num)
            continue_true = last_false - num
            if continue_true >= 4 and continue_true != 8:
                result = "l4z1all|%d-%d" % (continue_true, num)

    if result:
        # check if it is the first signal today
        found = False
        i = last_false
        rule = [False, True, True, True, True]
        while not found:
            if values[i:i+5] == rule:
                found = True
            else:
                i += 1
        current_id = sorted_matched[0][0][:6]
        last_id = sorted_matched[last_false][0][:6]

        if current_id != last_id:
            return result
        else:
            return None

    return result


def signal_l4z1_after(sorted_matched):
    """连４中１后具体信号"""
    result = None
    values = [s[1] for s in sorted_matched]
    rules = ["4-3", "5-1", "5-2", "5-3", "6-1", "6-3", "7-2", "7-3",
            "9-1", "9-2", "9-3", "10-2", "11-1", "11-2", "13-1", "13-2", "14-3"]
    for rule in rules:
        num1, num2 = map(int, rule.split("-"))
        # construct the pattern
        pattern = [True] * (num2 - 1) + [False] + [True] * num1 + [False]
        if np.allclose(values[:(num1+num2+1)], pattern):
            result = "l4z1h|" + rule
            logging.info("连４中１后具体信号 %s" % values[:(num1+num2+1)])
    return result
        
def signal_continue3_l4z1(sorted_matched):
    """连续3次连4中1信号"""
    result = None
    values = [s[1] for s in sorted_matched]
    rule = "(01{4,})(.*?)(01{4,})(.*?)(01{4,})"
    value_str = ''.join(map(str, map(int, values)))
    matched = re.match(rule, value_str)
    if matched is None:
        return result
    matched_str = matched.group()
    break_rule = "0{2,}1{4,}"
    if re.search(break_rule, matched_str):
        # matched break rule
        return result
    else:
        logging.info("连续３次连４中１信号 %s" % matched_str)
        return '3l4z1'

def signal_continue3_l3z1(sorted_matched):
    """连续3次连3中1信号"""
    result = None
    values = [s[1] for s in sorted_matched]
    rule = "(01{3}(?!1))(.*?)(01{3}(?!1))(.*?)(01{3}(?!1))"
    value_str = ''.join(map(str, map(int, values)))
    matched = re.match(rule, value_str)
    if matched is None:
        return result
    matched_str = matched.group()
    break_rule = "0{2,}1{3}"
    if re.search(break_rule, matched_str):
        # matched break rule
        return result
    else:
        logging.info("连续３次连３中１信号 %s" % matched_str)
        return '3l3z1'


def signal_4day_l4z1hbz(l4z1hbz_sequence):
    """连续４天出现连４中１后不中"""
    # get the past 4 days issues
    issue_ids = sorted(l4z1hbz_sequence.keys(), reverse=True)
    curr_id = issue_ids[0]
    curr_day = parser.parse(curr_id[:6])
    days = [(curr_day - timedelta(days=i)).strftime("%y%m%d") for i in range(4)]
    
    # collect signals
    proof_ids = []
    for i, day in enumerate(days):
        day_signal = []
        ids = []
        for issue_id in issue_ids:
            if issue_id.startswith(day):
                day_signal.append(l4z1hbz_sequence[issue_id])
                ids.append(issue_id)
            if issue_id[:6] < day:
                break
        if i == 0:
            # make sure today is signal and is the only signal
            if day_signal[0] != True or day_signal.count(True) > 1:
                return None
        else:
            if not np.any(day_signal):
                return None
        proof_ids.append(ids[day_signal.index(True)])

    logging.info("连续４天出现连４中１后不中 %s" % proof_ids)
    return "4day_l4z1hbz"

def signal_q4z1_after(sorted_matched, sorted_full_matched):
    """ 检测全４中１具体信号"""
    rules = ["1-1", "1-2", "1-3", "2-2", "3-3", "5-2"]
    match_values = [s[1] for s in sorted_matched]
    full_values = [s[1] for s in sorted_full_matched]

    for rule in rules:
        num1, num2 = map(int, rule.split("-"))
        first_part = [True] * (num2-1) + [False]
        if np.allclose(full_values[:num2], first_part):
            next_false_index = full_values.index(False, num2)
            if next_false_index - num2 >= 4: # full q4z1
                # check the matched luo/sha/leng ma
                checked_values = match_values[num2:next_false_index]
                count = checked_values.count(True)
                if count == num1:
                    return "q4z1h|%s" % rule
    return None


def compute_l4z1hbz(issue_id, matched, lottery):
    target_pattern = [True, False, True, True, True, True]
    pattern = []
    for i in range(len(target_pattern)):
        pattern.append(matched[issue_id])
        issue_id = lottery[issue_id]["previous"]
    return np.allclose(target_pattern, pattern)


def main():
    args = parse_args()
    run(args)

if __name__ == "__main__":
    main()
