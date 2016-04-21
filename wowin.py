#!/usr/bin/python
# -*- coding: utf-8 -*-
"""wowin.py: A client for automatize WoW (3.3.5) login using sockets and a variation of SRP6.
"""

from wrsp import Wrsp
import sys
import webbrowser
import requests
from BeautifulSoup import BeautifulSoup  # A wonderful module for HTML/XML parsing
import json

def hilite(string, status = False, bold = False):
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
    
    #print "Molten Autovote started..."
    url_0 = 'http://www.warmane.com/account/login'
    url = 'http://www.warmane.com/account'
    # Start a new session, to preserve the cookie
    global s  # So I can create the function points()
    #print "Trying to do a GET request to parse csrf-token..."
    s = requests.session()
    # Take session from the simple Molten index page
    t = s.get(url)
    #print t.text  # Cloudflare, need to bypass HERE TODO
    soup = BeautifulSoup(t.text)
    # Prendo token anti CSRF
    # <meta name="csrf-token" content="ZGRiNzQ3MWE2NWI5NTc5MDQ1M2E5ZjgzYTRhMjNhZjQ=">
    token = soup.find("meta", {"name": "csrf-token"})['content']
    #print "Il token CSRF è: ", token
    # The login payload
    login_payload = {
        'userID': username,
        'userPW': password
    }
    # The vote payload
    vote_payload = {
        'collectpoints': 'true'
    }

    #print "Logging in with POST request..."
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
        print hilite("Error:", False, True)
        print hilite(vote_response.json()['messages']['error'][0])
    else:
        print "Now you have: ",
        print hilite(vote_response.json()['messages'].get('points'), True)
        print " votepoints"
    # print "Request method: ", r.request.method
    # points()
    return 0

# Server data
host = "54.213.244.47"
port = 3724
# Get login data from file
f = file("accounts.txt", 'r')
for line in f.readlines():
    user, password = line.rstrip().split(":")
    mypacket = Wrsp(user, password, host)
    if mypacket.login():
        print hilite("User: " + user + " logged in-game succesfully!", True)
        mypacket.show_realm()
        # Open Login page to vote easily
        autovote(user, password)

    else:
        print "Login failed for: " + user

# user = "alexlorens"
# password = "lolloasd"
# mypacket = Wrsp(user, password, host)
# print mypacket.login()
# print mypacket.show_realm()


