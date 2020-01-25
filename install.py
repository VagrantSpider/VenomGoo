#!/usr/bin/evn python3


import os

GOO_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)))


print("Installing Requirements...")
os.system("pip3 install pymetasploit3 netifaces sqlite3 json")
print("Copying Files ...")
os.system("cp -r %s /opt" %GOO_PATH)
print("Linking script ...")
os.system("ln -s /opt/venomgoo/VenomGoo.py /usr/bin/venomgoo")
print("Done.")
