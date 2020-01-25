#!/usr/bin/evn python3

import os

print("Installing Requirements...")
os.system("pip3 install pymetasploit3 netifaces sqlite3 json")
print("Creating directory /opt/venomgoo ...")
os.system("mkdir -p /opt/venomgoo")
print("Copying Files ...")
os.system("cp ./* /opt/venomgoo/")
print("Linking script ...")
os.system("ln -s /opt/venomgoo/VenomGoo.py /usr/bin/venomgoo")
print("Done.")
