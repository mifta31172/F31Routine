#!/usr/bin/env python3
"""Builds directory.enc (AES-256-GCM, PBKDF2-SHA256 100000 rounds) for FELO 31.
Usage:  python3 make_directory.py students.txt  YOURCODE   > directory.enc
students.txt lines:  roll|Full name|mobile|optional nickname
KEEP students.txt on your own computer. Never commit it to GitHub: it holds the phone numbers in plain text."""
import sys, json, base64, os, re
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
PRE={'md','md.','mst','mst.','most','mohammad','mohammed','mohammed.','mohammod','shah','sayeed','soyed','mir','dewan','kazi','munshi'}
GEN={'islam','khatun','akter','akther','hossain','hassan','hasan','rahman','rahaman','ahmed','ahmmed','ahamed','roy','das','saha','khan','begum','chowdhury','sarker','molla','talukder','bhuiyan','sultana','jahan','parvin','binte','bintey','bin','ullah','uddin','ali','alam','mia','sikdar','sardar','mozumder','haque','nessa','rani','kumar','deb','biswas','dey'}
def nick(name):
    t=[w for w in re.split(r'\s+',name.strip()) if w]
    if len(t)==1: return t[0]
    core=[w for w in t if w.lower() not in PRE]
    last=core[-1]
    if last.lower() not in GEN and len(last)>=3: return last.strip('.')
    for w in core:
        if w.lower() not in GEN and len(w)>=3: return w.strip('.')
    return core[0].strip('.')
def build(rows,code):
    salt=os.urandom(16); iv=os.urandom(12)
    key=PBKDF2HMAC(hashes.SHA256(),32,salt,100000).derive(code.strip().upper().encode())
    pt=json.dumps(rows,ensure_ascii=False,separators=(',',':')).encode()
    ct=AESGCM(key).encrypt(iv,pt,None)
    b=lambda x:base64.b64encode(x).decode()
    return json.dumps({"v":1,"i":100000,"s":b(salt),"n":b(iv),"d":b(ct)},separators=(',',':'))
if __name__=='__main__':
    rows=[]
    for l in open(sys.argv[1],encoding='utf8'):
        p=[x.strip() for x in l.split('|')]
        if len(p)<3 or not p[0].isdigit(): continue
        rows.append([int(p[0]),p[1],p[3] if len(p)>3 and p[3] else nick(p[1]),p[2]])
    sys.stdout.write(build(rows,sys.argv[2]))
