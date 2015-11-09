#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Wei Wang"
__email__ = "tskatom@vt.edu"

import sys
import os
from selenium import webdriver


def login(units, tens):
    uname = "cp668899"
    passwd = "wsww0214"

    brow = webdriver.Chrome()
    url = "http://www.hu8r.com/weblogin.html?v=210"
    brow.get(url)
    brow.set_page_load_timeout(5)
    try: 
        name_slot = brow.find_element_by_id("username")
        name_slot.send_keys(uname)

        pwd_slot = brow.find_element_by_id("password")
        pwd_slot.send_keys(passwd)
    
        login_bt = brow.find_element_by_id("loginBTN")
        login_bt.click()
        
        notFound = True
        while notFound:
            try:
                cqssc = brow.find_element_by_id("SSC_CQSSC_475")
                cqssc.click()
                notFound = False
            except:
                print sys.exc_info()
                brow.implicitly_wait(1)

        # 选择类型
        rx = get_element(brow, brow.find_element_by_xpath, "//label[@prop='bet_playname_218168']")
        rx.click()
        
        game = get_element(brow, brow.find_element_by_xpath, 
                "//li[@rmk='bet_playremark_218170']")
        game.click()
        # choose method
        buyModel = get_element(brow, brow.find_element_by_xpath,
                "//select[@id='buyModel']/option[@value='0.01']")
        buyModel.click()
        # choose number
        ten_lis = get_element(brow, brow.find_elements_by_xpath, 
                "//ul[@id='row_number_d']/li")
        print ten_lis, tens
        for num in tens:
            ele = ten_lis[num]
            ele.click()

        unit_lis = get_element(brow, brow.find_elements_by_xpath, 
                "//ul[@id='row_number_e']/li")
        for num in units:
            ele = unit_lis[num]
            ele.click()

    except:
        print sys.exc_info()
    return brow

def get_element(driver, method, rule):
    notFound = True
    while notFound:
        try:
            ele = method(rule)
            notFound = False
        except:
            print sys.exc_info()
            driver.implicitly_wait(1)
            driver.set_page_load_timeout(5)
    return ele

if __name__ == "__main__":
    login()
