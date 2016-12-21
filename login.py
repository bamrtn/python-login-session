import sqlite3
import hashlib
import time
import os

def timingSComapre(a,b):
    if len(a) != len(b):
        return False
    c = True
    for x, y in zip(a, b):
        c &= (x == y)
    return c

def random32():
    return os.urandom(32).hex()

def newSessionID():
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    sql.execute("""SELECT * FROM Sessions ORDER BY SessionID DESC LIMIT 1""")
    data = sql.fetchone()
    return data[4]

DB = 'asd.db'

'''
UserLogin
Salt  Hash  UserName
'''

def login(passwd,user):
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    sql.execute("""SELECT * FROM UserLogin WHERE UserName=?""",(user,))
    data = sql.fetchone()
    if data != None:
        if timingSComapre(hashlib.sha256(bytes(data[0]+passwd,"utf-8")).hexdigest(), data[1]):
            sqlConn.close()
            return (True, data[2])
    sqlConn.close()
    return (False, '')

def changePassword(passwd,user):
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    salt = random32()
    sql.execute("""UPDATE UserLogin SET Salt=?, Hash=? WHERE UserName=?""",(salt, hashlib.sha256(bytes(salt+passwd,"utf-8")).hexdigest(),user))
    sqlConn.commit()
    sqlConn.close()
    return

def newUser(passwd,user):
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    salt = random32()
    sql.execute("""INSERT INTO UserLogin VALUES (?,?,?);""",(salt,hashlib.sha256(bytes(salt+passwd,"utf-8")).hexdigest(),user))
    sqlConn.commit()
    sqlConn.close()
    return

def delUser(user):
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    salt = random32()
    sql.execute("""DELETE FROM UserLogin WHERE UserName=?""",(user,))
    sqlConn.commit()
    sqlConn.close()
    return

'''
Sessions
Salt  Hash  Timeout  UserName  SessionID
'''

def checkSession(cookie):
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    data = cookie.split(':')
    if len(data)==2:
        sessionID = data[0]
        token = data[1]
        sql.execute("""SELECT * FROM Sessions WHERE SessionID=?""",(sessionID,))
        data = sql.fetchone()
        if data != None:
            if data[2] < time.mktime(time.gmtime()):
                if timingSComapre(hashlib.sha256(bytes(data[0]+token,"utf-8")).hexdigest(), data[1]):
                    sqlConn.close()
                    return (True, data[3])
    sqlConn.close()
    return (False, '')

def extendSession(sessionID, timeout):
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    token = random32()
    salt = random32()
    sql.execute("""UPDATE Sessions SET Salt=? ,Hash=? ,Timeout=? WHERE SessionID=?""",(salt,hashlib.sha256(bytes(salt+token,"utf-8")).hexdigest(),timeout,sessionID))
    sqlConn.commit()
    sqlConn.close()
    return token

def endSession(sessionID):
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    sql.execute("""DELETE FROM Sessions WHERE SessionID=?""",(sessionID,))
    sqlConn.commit()
    sqlConn.close()

def newSession(user, timeout):
    sqlConn = sqlite3.connect(DB)
    sql = sqlConn.cursor()
    token = random32()
    salt = random32()
    sessionID = newSessionID()
    sql.execute("""INSERT INTO Sessions VALUES (?,?,?,?,?)""",(salt,hashlib.sha256(bytes(salt+token,"utf-8")).hexdigest(),timeout,user,sessionID))
    sqlConn.commit()
    sqlConn.close()
    return token
