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
from wechat_sdk import WechatBasic, WechatConf
import config
import time
from wechat_sdk.exceptions import NeedLoginError
import ConfigParser
"""
Hint:
    连４中１表示连续４期或者４期以上的数字出现在落／杀／冷码后，然后出现一期不在，发送信号
"""

logging.basicConfig(filename='./log/scc.log', level=logging.INFO)


def init_wechat(token=None, cookies=None, login=False):
    credit = ConfigParser.ConfigParser()
    credit.read("./config.key")
    appid = credit.get("credential", "appid")
    appsecret = credit.get("credential", "AppSecret")

    conf = WebchatConf(token="abcdef", appid=appid, appsecret=appsecret)
    wechat = WechatBasic(conf=conf)
    return wechat

def load_users(wechat):
    followers = wechat.get_followers()
    users = {}
    for user in followers["data"]:
        uid = user["openid"]
        # get user info
        userinfo = wechat.get_user_info(uid)
        tags = userinfo["tagid_list"]
        users[uid] = {"tags": tags, "nickname": userinfo["nickname"]}
    return users

def send_message(wechat, message):
    #group_id = config.group_id
    content = message["content"]
    groups = message["groups"]
    max_retry = 3
    done = False
    tried = 0
    while tried < max_retry and not done:
        tried += 1
        try:
            users = load_users(wechat)
            for uid, info in users.items():
                try:
                    for tag in info["tags"]:
                        if tag in groups:
                            # send the message to the user
                            wechat.send_text_message(uid, content)
                            logging.info('Success[%s]' % info["nickname"])
                            break
                except Exception as e:
                    logging.warn('Faild to send message to user [%s] with error %s' % (uid, e))
            done = True
        except Exception as e:
            logging.info("Need to reinitiate Wechat")
            exc_type, exc_obj, exc_tb = sys.exc_info()
            err_msg = "Error: %s, in Line No %d" % (exc_type, exc_tb.tb_lineno)
            logging.info("Failed to send the Messge: [%s]" % err_msg)
            time.sleep(1)
            wechat = init_wechat(login=True)


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
    ap.add_argument('--port', type=str, default='5918', help='the ZMQ port')
    ap.add_argument('--issue_file', type=str, default='./issues/issues.csv')
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
    l3_matched = {}
    full_matched = {}# 匹配所有６码
    match_keys = ["luo_ma", "leng_1_ma", "leng_2_ma", "sha_ma"]
    l3_match_keys = ["luo_ma", "leng_1_ma", "leng_2_ma", "sha_ma", "leng_3_ma"]
    
    full_match_keys = match_keys + ["chuan_1", "chuan_2", "ge_ma"]
    for issue in issues[101:]:
        prev_id = lottery[issue]["previous"]
        numbers = lottery[issue]["numbers"]
        prev_code = codes[prev_id]
        flag, l3_flag, full_flag = update_match(lottery[issue], prev_code)
        matched[issue] = flag
        l3_matched[issue] = l3_flag
        full_matched[issue] = full_flag

    # compute the l4z1hbz
    l4z1hbz_seq = {}
    for issue in issues[108:]:
        l4z1hbz_seq[issue] = compute_l4z1hbz(issue, matched, lottery)

    return lottery, lot_miss_info, codes, matched, l3_matched, full_matched, l4z1hbz_seq

def compute_code(issue_id, dig, lottery, lot_miss_info):
    lot = lottery[issue_id]
    code = {}
    code["luo_ma"] = lot["numbers"][dig]
    miss = sorted(lot_miss_info[issue_id][dig].items(), key=lambda x:x[1], reverse=True)
    code["leng_1_ma"] = miss[0][0]
    code["leng_2_ma"] = miss[1][0]
    code["leng_3_ma"] = miss[2][0]
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
    l3_flag = False
    full_flag = False
    match_keys = ["luo_ma", "leng_1_ma", "leng_2_ma", "sha_ma"]
    l3_match_keys = ["luo_ma", "leng_1_ma", "leng_2_ma", "leng_3_ma", "sha_ma"]
   
    full_match_keys = match_keys + ["chuan_1_ma", "chuan_2_ma", "ge_ma"]
    for dig in range(3, 5):
        codes = prev_code[dig]
        for key in match_keys:
            if codes[key] == numbers[dig]:
                flag = True
        
        for key in l3_match_keys:
            if codes[key] == numbers[dig]:
                l3_flag = True

        for key in full_match_keys:
            if codes[key] == numbers[dig]:
                full_flag = True
    return flag, l3_flag, full_flag


def run(args):
    tz = pytz.timezone(pytz.country_timezones('cn')[0])
    now = datetime.now(tz)
    logging.info('Start Scc Monitoring at [%s]' % now.isoformat())

    # load the current issue files
    issue_file = args.issue_file
    port = args.port
    lottery, lot_miss_info, codes, matched, l3_matched, full_matched, l4z1hbz_seq = initiate_codes(issue_file)
    # record the information
    record_file = "./issues/record.csv"
    with open(record_file, 'w') as record_f:
        head = "%s\t%s\t%s\t%s\n" % ("期数", "号码", "4码", "6码")
        keys = sorted(full_matched.keys())
        for k in keys:
            nums = ''.join(map(str, lottery[k]["numbers"]))
            m4 = 'x' if matched[k] else 'o'
            m6 = 'x' if full_matched[k] else 'o'
            line = "%s\t%s\t%s\t%s\n" % (k, nums, m4, m6)
            record_f.write(line)

    previous = sorted(lottery.keys())[-1]
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    logging.info('Start to receiving subscription from SCC ingest process')
    wechat = init_wechat()
    wechat.login()
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
            flag, l3_flag, full_flag = update_match(lottery[cur_id], prev_code)
            matched[cur_id] = flag
            l3_matched[cur_id] = l3_flag
            full_matched[cur_id] = full_flag

            # update l4z1hbz
            l4z1hbz_seq[cur_id] = compute_l4z1hbz(cur_id, matched, lottery)

            previous = cur_id

            # generate the signal
            sorted_matched = sorted(matched.items(), key=lambda x:x[0], reverse=True)
            l3_sorted_matched = sorted(l3_matched.items(), key=lambda x:x[0], reverse=True)

            sorted_full_matched = sorted(full_matched.items(), key=lambda x:x[0], reverse=True)

            signals = generate_signals(sorted_matched, sorted_full_matched, l4z1hbz_seq)
            l3_signals = generate_signals(l3_sorted_matched, sorted_full_matched, l4z1hbz_seq)

            # write the record

            with open(record_file, 'a+') as record_f:
                nums = ''.join(map(str, lottery[cur_id]["numbers"]))
                m4 = 'x' if matched[cur_id] else 'o'
                l3_m4 = 'x' if matched[cur_id] else 'o'
                m6 = 'x' if full_matched[cur_id] else 'o'
                line = "%s\t%s\t%s\t%s\t%s\n" % (cur_id, nums, m4, l3_m4, m6)
                record_f.write(line)

            if len(signals):
                try:
                    messages = template(signals, lottery[cur_id], codes[cur_id], l3=False, level="entry")
                    for message in messages:
                        logging.info("收到信号: %s at [%s]" % (message["content"], datetime.now(tz).isoformat()))
                        send_message(wechat, message)
                except Exception as e:
                    err_msg = "Send Message Error %s at %s" % (e, datetime.now(tz).isoformat())
                    logging.info(err_msg)

            if len(l3_signals):
                try:
                    messages = template(l3_signals, lottery[cur_id], codes[cur_id], l3=True, level="middle")
                    for message in messages:
                        logging.info("收到信号: %s at [%s]" % (message["content"], datetime.now(tz).isoformat()))
                        send_message(wechat, message)
                except Exception as e:
                    err_msg = "Send Message Error %s at %s" % (e, datetime.now(tz).isoformat())
                    logging.info(err_msg)

    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        err_msg = "Error: %s, in Line No %d" % (exc_type, exc_tb.tb_lineno)
        print sys.exc_info()
        logging.info(err_msg)


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

    """

    signal = signal_l4z1_after_new(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测连４中１后:[%s]" % signal)

    signal = signal_1buzhong_new(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测１不中[%s]" % signal)

    """
    signal = signal_2buzhong(sorted_matched)
    if signal:
        signals.append(signal)
    logging.info("检测２不中[%s]" % signal)

    signal = signal_q4z1_after(sorted_matched, sorted_full_matched)
    if signal:
        signals.append(signal)
    logging.info("全４中１后具体信号 [%s]" % signal)
    """
    return signals


def template(signals, cur_lot, cur_code, l3=False, level="entry"):
    sig2name = {"l4z1": "连４中１", "1bz": "１不中", "2bz": "２不中",
            "l4z1h": "连４中１后", "3l4z1":"连续３次连４中１后",  "3l3z1": "连续３次连３中１后",
            "4day_l4z1hbz": "连续４天出现连４中１后不中", "q4z1h": "全４中１后"}
    # load signal group information
    signal_groups = json.load(open('./group_setting.json'))

    code2name = {"luo_ma": "落码", "leng_1_ma": "冷１码", "leng_2_ma": "冷２码", "leng_3_ma": "冷 3 码",
            "sha_ma": "杀码", "chuan_1_ma": "传１码", "chuan_2_ma":"传２码", "ge_ma": "隔码"}

    dig2name = {3: "十位", 4: "个位"}
    # issue message
    messages = []
    # signal message
    for i, signal in enumerate(signals):
        message = "当前期数:%s, 开奖号码: %s\n" % (cur_lot["issue"], "".join(map(str,cur_lot["numbers"])))
        sig_info = signal.split("|")
        if len(sig_info) > 1:
            name = sig2name[sig_info[0]] + "_" + sig_info[1]
        else:
            name = sig2name[sig_info[0]]
        message += "信号 %d: %s\n" % (i+1, name)

        # code message
        message += "码信息\n"
        #code_order = ["luo_ma", "sha_ma", "leng_1_ma", "leng_2_ma", "ge_ma", "chuan_1_ma", "chuan_2_ma"]
        code_order = ["luo_ma", "sha_ma", "leng_1_ma", "leng_2_ma"]
        if l3:
            code_order.insert(4, "leng_3_ma")
        for i in range(3, 5):
            dig_name = dig2name[i]
            message += "%s: " % dig_name
            for code in code_order:
                message += "%d " % (cur_code[i][code])
            message += "\n"
        
        groups = signal_groups[level]get(sig_info[0])
        
        messages.append({"content": message, "groups": groups})
    return messages


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

def signal_1buzhong_new(sorted_match):
    sig_alg = [signal_1buzhong, signal_2buzhong, signal_3buzhong]
    result = None
    for alg in sig_alg:
        r = alg(sorted_match)
        if r:
            result = r
    if result:
        result = '1bz|1-' + result[0]
    return result


def signal_1buzhong(sorted_matched):
    """1不中后信号"""
    result = None
    values = [s[1] for s in sorted_matched[-1:-50:-1]]
    value_str = ''.join(map(str, map(int, values)))
    rule = "10{1,}10"
    if re.match(rule, value_str):
        result = "1bz"
    return result

def signal_2buzhong(sorted_matched):
    """2不中后信号"""
    result = None
    values = [s[1] for s in sorted_matched[-1:-50:-1]]
    value_str = ''.join(map(str, map(int, values)))
    rule = "110{1,}10"
    if re.match(rule, value_str):
        result = "2bz"
    return result

def signal_3buzhong(sorted_matched):
    """3不中后信号"""
    result = None
    values = [s[1] for s in sorted_matched[-1:-50:-1]]
    value_str = ''.join(map(str, map(int, values)))
    rule = "1110{1,}10"
    if re.match(rule, value_str):
        result = "3bz"
    return result


def signal_l4z1_after(sorted_matched):
    """连４中１后具体信号"""
    result = None
    values = [s[1] for s in sorted_matched[-1:-50:-1]]
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

def signal_l4z1_after_new(sorted_matched):
    """连4中1后信号新算法"""
    result = None
    values = [s[1] for s in sorted_matched[-1:-50:-1]]
    sufix_rule = [1, 2, 3]
    for r in sufix_rule:
        sufix_pattern = [True] * (r - 1) + [False]
        if np.allclose(values[:r], sufix_pattern):
            # check the prefix: detect the continue Trues
            true_idx = 0
            while values[r + true_idx]:
                true_idx += 1
            if true_idx >= 4:
                result = "l4z1h|%d-%d" % (true_idx, r)
    return result


def signal_continue3_l4z1(sorted_matched):
    """连续3次连4中1信号"""
    result = None
    values = [s[1] for s in sorted_matched[-1:-50:-1]]
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
    values = [s[1] for s in sorted_matched[-1:-50:-1]]
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
    match_values = [s[1] for s in sorted_matched[-1:-50:-1]]
    full_values = [s[1] for s in sorted_full_matched[-1:-50:-1]]

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
