# miningcheckhash
Check the hashs on Ethos console and if is less then 30 send a reboot and email command
#!/usr/bin/env python
# -*- coding:utf-8 -*-
""" Reboot host if hash value < limit"""
"""
1) Install python
apt-get install python

2). Upload host_reboot.py to a folder (\home\app\):

3)  Run cmd:
  python  \home\app\host_reboot.py

"""


HOST_IP =  '10.0.0.33'

TEST_REGIME = 0   # 1- No reboot only error messages;   0 - reboot
HASH_LIMIT = 30
SERVER_URL = 'http://aab1cc.ethosdistro.com/?json=yes'
LOG_FILE = 'host_reboot.log'
#LOG_FILE = '/var/log/host_reboot.log'

INTERFACES = [
    "eth0",
    "eth1",
    "eth2",
    "wlan0",
    "wlan1",
    "wifi0",
    "ath0",
    "ath1",
    "ppp0",
    ]

EMAIL_SUBJECT = 'HOST REBOOT'
EMAIL_FROM = 'test@gmail.com'
EMAIL_TO = 'test@gmail.com'
SMTP_SERVER = 'smtp.googlemail.com'
SMTP_PORT = 465
EMAIL_LOGIN='login'
EMAIL_RWD = 'password'


import requests
import json
import os
import logging,logging.handlers
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import socket
if os.name != "nt":
    import fcntl
    import struct
    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
            ifname[:15]))[20:24])


url = SERVER_URL
headers = {'Accept': 'application/json'}
logger = None

def main():
    """ GET URL and parse miner_hashes from JSON """
    try :
#        cur_ip1 = get_ip_address()
#        logger.info("Cuurent host ip=" + str(cur_ip1))
        cur_ip = get_lan_ip();
        logger.info("Cuurent host ip=" + str(cur_ip))
        HOST_IP = cur_ip

        resp = requests.get(url, headers=headers)
        jso = json.loads(resp.content)
        rigs = jso.get('rigs')
        logger.info ( 'Get JSON OK')
        if rigs is not None:
            for k, v in rigs.items():
                v_ip = v.get('ip')
                logger.info ( ' Host:' + str(v_ip) )
                if v_ip is not None and HOST_IP == v_ip:
                    v_hashes = v.get('miner_hashes')
                    if v_hashes is not None:
                        logger.info ( ' Host_ip found OK. miner_hashes:' + str(v_hashes))
                        mainer_hashes = [float(i) for i in v_hashes.split()]
                        reboot_needed = 0
                        all_zero = 1
                        for mn in mainer_hashes:
                            if mn > 0:
                                all_zero = 0
                            if mn < HASH_LIMIT and mn > 0:
                                logger.error ( v['ip'] + ' LIMIT IS OVER ' + str(mn))
                                reboot_needed = 1
                                break
                            if mn == 0 and all_zero == 0:
                                logger.error ( v['ip'] + ' LIMIT IS OVER ' + str(mn))
                                reboot_needed = 1
                                break

                    if reboot_needed:
                        logger.error ( 'HOST WILL BE REBOOTED')
                        email_text = 'HOST %s  WILL BE REBOOTED. miner_hashes= %s' % (v_ip, v_hashes)
                        if TEST_REGIME!=1:
                            os.system('reboot')
                        send_email(email_text)
                    else:
                        logger.info ( 'All is OK.')
        else:
            logger.error('No rigs found')

        return 1
    except Exception as err:
        logger.error("Ant error found  %s" % str(err))
        return  0



def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = INTERFACES
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip


def send_email(text):
    COMMASPACE = ', '
    msg = MIMEMultipart()
    msg['Subject'] = EMAIL_SUBJECT

    me = EMAIL_FROM
    family = EMAIL_TO
    msg['From'] = me
    msg['To'] = COMMASPACE.join(family)
    msg.preamble = EMAIL_SUBJECT

    body = MIMEText(text)
    msg.attach(body)
    try:
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(EMAIL_LOGIN, EMAIL_RWD)
        server.sendmail(me, family, msg.as_string())
        server.quit()
        logger.info("SEND email message OK." )

    except Exception as err:
        logger.error("SEND email error:  %s" % str(err))
        return  0


if __name__ == "__main__":

    FORMAT = "%(asctime)-15s %(message)s"
    logging.basicConfig(format=FORMAT,level=logging.INFO,datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger("host_reboot")
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024000, backupCount=5)
    logger.addHandler(handler)
    fmt = logging.Formatter(FORMAT,datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(fmt)

    logger.info("Start application")


    ret = main()
    exit (ret)
