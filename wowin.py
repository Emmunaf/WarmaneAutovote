#!/usr/bin/python
# -*- coding: utf-8 -*-
"""wowin.py: A client for automatize WoW (3.3.5) login
                using sockets and a variation of SRP6.
It is be able to autovote too.
Edit accounts.txt file in the following format to use this script:

username:password
username2:password2

Requirements:
    pip install bs4
    pip install schedule
"""

import socket
import time
import schedule
import datetime
from wrsp import Wrsp
import sys
import requests
from BeautifulSoup import BeautifulSoup  # A wonderful module for HTML parsing
# import json


def hilite(string, status=False, bold=False):
    """If tty highligth the output."""

    if not sys.stdout.isatty():
        return string
    attr = []
    if status:
        attr.append('32')  # Green
    else:
        attr.append('31')  # Red
    if bold:
        attr.append('1')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)


def autovote(username, password):
    """Starts the autovote."""

    url_0 = 'http://www.warmane.com/account/login'
    url = 'http://www.warmane.com/account'
    # Start a new session, to preserve the cookie
    global s
    s = requests.session()
    # Take session and anti-csrf Token
    t = s.get(url)
    soup = BeautifulSoup(t.text)
    # <meta name="csrf-token" content="ZGRi...hZjQ=">
    token = soup.find("meta", {"name": "csrf-token"})['content']
    # The login POST payload
    login_payload = {
        'userID': username,
        'userPW': password
    }
    # The vote POST payload
    vote_payload = {
        'collectpoints': 'true'
    }
    login_headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Origin': 'http://www.warmane.com',
        'X-CSRF-Token': token,
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Referer': url_0,
        'Accept-Encoding': 'gzip, deflate'
    }
    vote_headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Origin': 'http://www.warmane.com',
        'X-CSRF-Token': token,
        'X-Requested-With': 'XMLHttpRequest',
        'Accept-Language': 'it-it',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Referer': url,
        'Accept-Encoding': 'gzip, deflate'
    }
    l_response = s.post(url_0, data=login_payload, headers=login_headers)
    vote_response = s.post(url, data=vote_payload, headers=vote_headers)
    if vote_response.json()['messages'].has_key('error'):
        print hilite("Error:", False, True)  # Bold
        print hilite(vote_response.json()['messages']['error'][0])
    else:
        print "Now you have: ",
        print hilite(vote_response.json().get('points')[0], True)
        print " votepoints"


def main():
    # Server data
    host = "logon.warmane.ru"
    # port = 3724
    # Get login data from file
    f = file("accounts.txt", 'r')
    for line in f.readlines():
        user, password = line.rstrip().split(":")
        mypacket = Wrsp(user, password, socket.gethostbyname(host))
        if mypacket.login():
            print hilite("User " + user + " logged in-game succesfully!", True)
            mypacket.show_realm()
            # Open Login page to vote easily
            autovote(user, password)
        else:
            print "Login failed for: " + user

    print "End of daily vote:", str(datetime.date.today())

main()
schedule.every().day.at("03:00").do(main, 'Autovoting...')
while True:
    schedule.run_pending()
    time.sleep(60)  # Wait one minute
