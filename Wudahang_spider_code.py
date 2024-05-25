# -*- coding: utf-8 -*-
"""
Created on Sun Apr  7 19:23:22 2024

@author: Administrator
"""

import requests
import json
import urllib3
import base64
from bs4 import BeautifulSoup
from random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pandas as pd

urllib3.disable_warnings()


def randomstring(length):
    strindex = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
    retnstr = ""
    for i in range(1,length+1):
        retnstr = retnstr + strindex[randint(0,47)]
        i = i + 1
    return retnstr


def get_encrypted_password(encrypted_key):
    aeskey_replaced = encrypted_key.replace("/(^\s+)|(\s+$)/g", "")
    aeskey_replaced = aeskey_replaced.encode("utf8")

    # generating IV value
    iv = randomstring(16).encode("UTF-8")

    # padding original password using pkcs7
    original = "hiddened"  # this is the original password
    original = randomstring(64) + original
    original = original.encode("utf8")
    original_padding = pad(original, AES.block_size, "pkcs7")

    # generating cipher and encrypting AES
    cipher = AES.new(aeskey_replaced, AES.MODE_CBC, iv)
    password_encrypted = cipher.encrypt(original_padding)
    password_post = base64.b64encode(password_encrypted)
    password_post = password_post.decode("utf8")
    return password_post


def auth_login():
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cache-Control": "max-age=0",
        "Content-Type": 'application/x-www-form-urlencoded',
        'origin': "https://authserver.ucass.edu.cn",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"
    }
    session.headers = headers
    authserver_url = "https://authserver.ucass.edu.cn/authserver/login"
    authserver = session.get(url=authserver_url, headers=headers, verify=False)
    authserver_cookies = authserver.cookies

    # get aeskey and execution cookies to login
    authserver_page = authserver.text
    soup = BeautifulSoup(authserver_page, 'html.parser')
    execution = soup.find(id="execution").get("value")
    aeskey = soup.find(id="pwdEncryptSalt").get("value")
    password = get_encrypted_password(aeskey)

    studentdata = {
        "username": "annoymous",
        "password": password_post,
        "captcha": "",
        "_eventId": "submit",
        "cllt": "userNameLogin",
        "dllt": "generalLogin",
        "lt": "",
        "execution": execution
    }

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cache-Control": "max-age=0",
        'origin': "https://authserver.ucass.edu.cn",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"
    }
    cookies = requests.utils.dict_from_cookiejar(authserver_cookies)
    cookies.update({"org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE": "zh_CN"})
    cookies
    authserver_login = session.post(url=authserver_url, headers=headers, cookies=cookies, data=studentdata,
                                    verify=False)
    r_response = authserver_login.headers
    acl_poly = r_response['Set-Cookie'].split()[0][9:-1]
    return acl_poly


def get_patentcookies(acl_poly):
    #simulation of login process of vpn
    url_getcookies = "https://libdb.ucass.edu.cn/api/acl_user/financeLoginssky?ticket=ST-739933-wUCZyJ9xUZcxweI1Uz-bGqJ-WnQciapserver2"
    headers = {
        #    "Origin": 'https://10htbprol1htbprol10htbprol9prodhtbl8888-p.libdb.ucass.edu.cn',
        #    "Referer": 'https://10htbprol1htbprol10htbprol9prodhtbl8888-p.libdb.ucass.edu.cn',
        #    "Host": '10htbprol1htbprol10htbprol9prodhtbl8888-p.libdb.ucass.edu.cn',
        "Content-Type": 'application/x-www-form-urlencoded;application/octet-strea;application/vnd.ms-excel;charset=UTF-8',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"
    }
    cookies = {
        #    "Origin": 'https://10htbprol1htbprol10htbprol9prodhtbl8888-p.libdb.ucass.edu.cn',
        #    "Referer": 'https://10htbprol1htbprol10htbprol9prodhtbl8888-p.libdb.ucass.edu.cn',
        #    "Host": '10htbprol1htbprol10htbprol9prodhtbl8888-p.libdb.ucass.edu.cn',
        "acl-poly": acl_poly,
    }
    r = requests.get(url=url_getcookies, headers=headers, cookies=cookies, verify=False)
    aclpoly_new = r.headers['Set-Cookie'].split()[0][9:-1]
    return aclpoly_new


def get_patentlist(acl_poly, countrycode, patent_type, start_date, end_date):
    headers = {
        "Content-Type": 'application/x-www-form-urlencoded;application/octet-strea;application/vnd.ms-excel;charset=UTF-8',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"
    }

    patent_url = 'https://10htbprol1htbprol10htbprol9prodhtbl8888-p.libdb.ucass.edu.cn/patentinformation/patentCon/combineSearch'
    text = "page=1&pageSize=10000&submitApplication=" + countrycode + "&sourceFlag=&patentOwnType=" + patent_type + "&patentOwnFirstField=patent_own_first&patentOwnFirst=&patentOwnField=patent_own&patentOwn=&dateField=apply_date&startDate=" + str(
        start_date) + "&" + str(end_date) + "=&wipoField=wipoindustry_category_name&wipoIndustryCategoryName=&nationalField=national_industries_classification_code&nationalIndustriesClassificationName=&"
    cookies = {
        'acl-poly': acl_poly,
        'userName': 'annoymous',
        'userPwd': 'sky1foefoe3567'
    }
    patent = session.post(patent_url, data=text, cookies=cookies, headers=headers, verify=False)
    patent_list = patent.json()['data']['list']
    return patent_list


def patent_list_to_df(list):
    patent_list_df = pd.DataFrame.from_dict(list)
    return patent_list_df


cookie = auth_login()
patent_cookies = get_patentcookies(cookie)
patentlist = get_patentlist(patent_cookies, "CN", "2024-01-10", "2024-04-12")
patent_list_df = pd.DataFrame.from_dict(patentlist)
patent_list_df.to_excel("patent.xlsx")#save the patent data