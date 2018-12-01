#!/usr/bin/env python3
from PythonClasses.User_Info_DB_Class import User_Info_DB
import Constants
import time

user_info_db = User_Info_DB()
user_info_db.add_user(user_id=135, ip="192.168.31.31")
user_info_db.add_user(user_id=133, ip="192.168.31.128")
user_info_db.add_record(user_id=133, behavior="DoS_ATK")
print(user_info_db.check_user(user_id=133))

user_info_db.add_user(user_id=999, ip="192.168.31.128")

print(user_info_db.check_ip("192.168.31.128"))
print(user_info_db.check_ip("192.168.31.31"))
print(user_info_db.check_ip("192.168.31.131")) # new ip



from PythonClasses.SHA1_Class import SHA1
import hashlib

m = "abc"
S = SHA1()
hashed = S.hash(m.encode())
print(hashed)

hashlib_rst = hashlib.sha1(m.encode()).hexdigest()
print(hashed)


from PythonClasses.HMAC_Class import HMAC
import hmac

m, k = "123", "oqwiejrhaskdf"

print(HMAC(m=m, k=k))

print(hmac.new(k.encode('utf-8'), m.encode('utf-8'), hashlib.sha1).hexdigest())

print(m)


import PythonClasses.Number_Package as npkg
from PythonClasses.RSA_Class import RSA
import numpy as np
p, q, N, e, d = RSA().random_private_key()
print(p, q, N, e, d)
