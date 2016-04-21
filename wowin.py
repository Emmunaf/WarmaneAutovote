#!/usr/bin/python
# -*- coding: utf-8 -*-
"""wowin.py: A client for automatize WoW (3.3.5) login using sockets and a variation of SRP6.
"""

from wrsp import Wrsp
import sys
import webbrowser

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

# Server data
host = "54.213.244.47"
port = 3724
# Get login data from file
f = file("accounts.txt", 'r')
for line in f.readlines():
    user, password = line.rstrip().split(":")
    mypacket = Wrsp(user, password, host)
    if mypacket.login():
        print hilite("User: " + user + " logged succesfully!", True)
        mypacket.show_realm()
        # Open Login page to vote easily
        url = 'http://www.warmane.com/account/'
        # Open URL in a new tab, if a browser window is already open.
        #webbrowser.open_new_tab(url + 'login')
        webbrowser.open_new(url + 'login')
        print hilite("Press Enter to continue")
        raw_input()

    else:
        print "Login failed for: " + user

# user = "alexlorens"
# password = "lolloasd"
# mypacket = Wrsp(user, password, host)
# print mypacket.login()
# print mypacket.show_realm()

