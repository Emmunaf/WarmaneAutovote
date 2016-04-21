#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Molvoter.py
#  Molten-Autovoter it's a simple script that votes in all 3 sites to obtain max points
#  Copyright 2013 Emanuele Munafò <emp3hack@Ema-PC>
#

import datetime
from threading import Timer
import json  # Required to do json requests for logging in and Auto-Vote
import requests  # A wonderful module for web requests
import time  # To use sleep function
from BeautifulSoup import BeautifulSoup  # A wonderful module for HTML/XML parsing
import re
from optparse import OptionParser


def main():
    """Starts the autovote."""
    
    print "Molten Autovote started..."
    url_0 = 'http://www.warmane.com/account/login'
    url = 'http://www.warmane.com/account'
    # Start a new session, to preserve the cookie
    global s  # So I can create the function points()
    print "Trying to do a GET request to parse csrf-token..."
    s = requests.session()
    # Take session from the simple Molten index page
    t = s.get(url)
    print t.text  # Cloudflare, need to bypass HERE TODO
    soup = BeautifulSoup(t.text)
    # Prendo token anti CSRF
    # <meta name="csrf-token" content="ZGRiNzQ3MWE2NWI5NTc5MDQ1M2E5ZjgzYTRhMjNhZjQ=">
    token = soup.find("meta", {"name": "csrf-token"})['content']
    print "Il token CSRF è: ", token
    # The login payload
    login_payload = {
        'userID': username,
        'userPW': password
    }
    # The vote payload
    vote_payload = {
        'collectpoints': 'true'
    }

    print "Logging in with POST request..."
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

    # response = requests.post(url_0, data=json.dumps(data), headers=headers)
    l_response = s.post(url_0, data=login_payload, headers=login_headers)
    vote_response = s.post(url, data=vote_payload, headers=vote_headers)
    if vote_response.json()['messages']['error']:
        print "Error:"
        print vote_response.json()['messages']['error'][0]
    else:
        print "Now you have: ",
        print vote_response.json()['messages'].get('points')
        print " votepoints"
    # print "Request method: ", r.request.method
    # points()
    return 0


def points():
    g = s.get('http://www.warmane.com/account')
    print g.text
    # <span class="myPoints">102</span>
    soup = BeautifulSoup(g.text)
    for link in soup.findAll('span', attrs={'class': 'myPoints'}):
        # Converto da [type(link)] = classe beautiful soap a stringa, poi tramite regex prendo solo i numeri
        link = str(link)
    return re.sub("\D", "", link)


if __name__ == '__main__':
    accounts = [0, 1]
    accounts[0] = ['Username', 'Password', 'Orario']
    accounts[1] = ['Username', 'Password', 'Orario']
    try:
        # Info & Instruction & Usage
        print("\n\tMolten Vote Hack 3.0 - Automates the vote process for you on Molten-WoW.\n" +
              "\tCopyleft Emanuele Munafò <ema.muna95@gmail.com>\n" +
              "\n\tJust Log-in with your e-mail and password.\n" +
              "\tThe vote will be automatic.\n\n")
        parser = OptionParser(usage="usage: %prog [options] -u [user] -p [password]\n\n" +
                                    "\t-h Show help\n" +
                                    "\t-u [username]\n" +
                                    "\t-p [password]\n\n")
        parser.add_option("-u", "--user", action="store", dest="username", default=None,
                          help="The username for the login in the site of Molten.")
        parser.add_option("-p", "--password", action="store", dest="password", default=None,
                          help="The password for the login in the site of Molten.")
        (o, args) = parser.parse_args()
        if o.username is None:
            parser.error("No password specified.")
        elif o.password is None:
            parser.error("No password specified.")
        else:
            # Take user & pass
            username = o.username
            password = o.password
            main();
    except Exception as e:
        print(e)
