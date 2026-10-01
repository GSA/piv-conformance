#!/usr/bin/env python3
"""Synthetic CBEFF headers and SAN links. Payload/signature bytes are placeholders.
No biometric sample or real identifier is used; these are header/link assertions.
"""
from pathlib import Path
import hashlib,json,struct
ROOT=Path(__file__).resolve().parents[2]
vectors=[]
def add(id,method,data,expected='PASS',kind='positive'):
    rule='76-CBEFF-HEADER' if method=='fingerprintHeader' else '73-UUID-CERT-LINK'
    vectors.append(dict(id=id,method=method,input_hex=data.hex(),expected=rule if expected=='FAIL' else expected,kind=kind,requirements=[rule],sha256=hashlib.sha256(data).hexdigest()))
def der(t,v):
    n=len(v);return bytes([t])+ (bytes([n]) if n<128 else b'\x81'+bytes([n]))+v
def names(*uris):return der(0x30,b''.join(der(0x86,u.encode('ascii')) for u in uris))
uuid='00112233-4455-4677-8899-aabbccddeeff'
add('uuid-link-correct','cardUuid',names('urn:uuid:'+uuid))
add('uuid-link-upper','cardUuid',names('URN:UUID:'+uuid.upper()))
add('uuid-link-multiple','cardUuid',names('https://example.invalid','urn:uuid:'+uuid,'urn:uuid:11223344-5566-4778-8899-aabbccddeeff'))
for name,text in [('mismatch','urn:uuid:11223344-5566-4778-8899-aabbccddeeff'),('wrong-prefix','https://'+uuid),('short-groups','urn:uuid:1-2-3-4-5'),('no-hyphens','urn:uuid:'+uuid.replace('-','')),('trailing','urn:uuid:'+uuid+'x')]:add('uuid-link-'+name,'cardUuid',names(text),'FAIL','negative')
add('uuid-link-empty','cardUuid',names(),'FAIL','negative')
add('uuid-link-truncated','cardUuid',names('urn:uuid:'+uuid)[:-1],'FAIL','malformed')
header=bytearray(90)
header[0:12]=b'\x03\x0d'+struct.pack('>IHHH',1,1,0x1b,0x201)
date=bytes([20,26,9,30,12,0,0,ord('Z')]);header[12:20]=date;header[20:28]=date;header[28:36]=bytes([20,32,9,30,12,0,0,ord('Z')])
header[36:41]=bytes([0,0,8,0x80,100]);header[41:49]=b'TestOnly';header[59:84]=bytes(range(25));header[88:90]=b'\1\1'
add('cbeff-header-valid','fingerprintHeader',header)
for index,value,name in [(0,2,'version'),(1,15,'encrypted'),(8,1,'owner'),(11,2,'format'),(38,2,'modality'),(39,0x20,'processing'),(40,101,'quality-high'),(40,253,'quality-low'),(84,1,'rfu'),(59,255,'fascn-link'),(12,100,'year-pair'),(14,13,'month'),(15,31,'calendar'),(16,24,'hour'),(19,ord('z'),'utc'),(20,19,'start-before-creation'),(41,31,'creator-control')]:
    b=bytearray(header);b[index]=value;add('cbeff-'+name,'fingerprintHeader',b,'FAIL','boundary' if name in ['quality-high','quality-low','hour','year-pair','calendar'] else 'negative')
for q in [-2,-1,0,100]:
    b=bytearray(header);b[40]=q&255;add('cbeff-quality-'+str(q),'fingerprintHeader',b,kind='boundary')
for size in [0,1,0xffffffff]:
    b=bytearray(header);b[2:6]=struct.pack('>I',size);add('cbeff-bdb-'+str(size),'fingerprintHeader',b,'PASS' if size==1 else 'FAIL','boundary')
b=bytearray(header);b[6:8]=b'\0\0';add('cbeff-empty-signature','fingerprintHeader',b,'FAIL','negative')
b=bytearray(header);b[41:59]=b'A'*18;add('cbeff-no-creator-terminator','fingerprintHeader',b,'FAIL','negative')
b=bytearray(header);b[41:59]=b'A'*17+b'\0';add('cbeff-creator-17','fingerprintHeader',b,kind='boundary')
for size in [0,8,87,88,89]:add('cbeff-truncated-'+str(size),'fingerprintHeader',header[:size],'FAIL','malformed')
dest=ROOT/'conformancelib/src/main/resources/standards/current-linked.tsv'
dest.write_text('# id\tmethod\texpected-rule-or-PASS\thex\n'+''.join(f"{v['id']}\t{v['method']}\t{v['expected']}\t{v['input_hex']}\n" for v in vectors))
(ROOT/'standards/linked-vectors.json').write_text(json.dumps(vectors,indent=2)+'\n')
print(len(vectors),'vectors',hashlib.sha256(dest.read_bytes()).hexdigest())
