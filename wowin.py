#!/usr/bin/python
# -*- coding: utf-8 -*-
"""wowin.py: A client for automatize WoW (3.3.5) login using sockets and a variation of SRP6.
"""

from wrsp import Wrsp

# Server data
host = "54.213.244.47"
port = 3724
# Get login data from file
f = file("accounts.txt", 'r')
for line in f.readlines():
    user, password = line.rstrip().split(":")
    mypacket = Wrsp(user, password, host)
    if mypacket.login():
        print "User: " + user + "logged succesfully!"
        mypacket.show_realm()
    else:
        print "Login failed for: " + user

# user = "alexlorens"
# password = "lolloasd"
# mypacket = Wrsp(user, password, host)
# print mypacket.login()
# print mypacket.show_realm()
