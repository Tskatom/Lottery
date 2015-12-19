#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Wei Wang"
__email__ = "tskatom@vt.edu"

import sys
import os
import time
import zmq


def run(port, his_file):
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind("tcp://*:%s" % port)

    with open(his_file):
        for line in open(his_file):
            line = line.strip()
            print line
            socket.send_string(line)
            time.sleep(0.01)

def main():
    port = "6000"
    if len(sys.argv) > 1:
        port = sys.argv[1]

    his_file = "./issues/historical_issues.csv"
    run(port, his_file)

if __name__ == "__main__":
    main()

