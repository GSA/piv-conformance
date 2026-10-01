#!/usr/bin/env python3
"""Independent DER fixtures for algorithm/parameter checks, not signature proof.

RSA modulus bytes test representation/size only (not prime generation).
EC public points are the published SEC2 base points. No cardholder data or keys.
"""
from pathlib import Path
import hashlib
import json
ROOT=Path(__file__).resolve().parents[2]
vectors=[]

def der(t,v):
    n=len(v); l=bytes([n]) if n<128 else bytes([128+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([t])+l+v
def seq(*v): return der(48,b''.join(v))
def integer(n):
    if n<0:return der(2,b'\xff')
    b=n.to_bytes(max(1,(n.bit_length()+7)//8),'big')
    return der(2,(b'\0' if b[0]&128 else b'')+b)
def oid(text):
    nums=list(map(int,text.split('.')));result=bytearray([40*nums[0]+nums[1]])
    for n in nums[2:]:
        group=[n&127];n>>=7
        while n:group.insert(0,128+(n&127));n>>=7
        result.extend(group)
    return der(6,bytes(result))
NULL=b'\x05\0'
def alg(o,p=b''):return seq(oid(o),p)
RSA='1.2.840.113549.1.1.1';EC='1.2.840.10045.2.1';P256='1.2.840.10045.3.1.7';P384='1.3.132.0.34'
SHA256='2.16.840.1.101.3.4.2.1';SHA384='2.16.840.1.101.3.4.2.2';PSS='1.2.840.113549.1.1.10'
def rsa(n,e=65537,p=NULL): return seq(alg(RSA,p),der(3,b'\0'+seq(integer((1<<(n-1))+1),integer(e))))
def ec(curve,point,p=None):return seq(alg(EC,oid(curve) if p is None else p),der(3,b'\0'+point))
def add(id,method,data,expected='PASS',kind='positive',rules=None):
    vectors.append(dict(id=id,method=method,input_hex=data.hex(),expected=expected,kind=kind,requirements=rules or [expected],sha256=hashlib.sha256(data).hexdigest()))
for n in [1024,2047,2048,2049,3071,3072,3073,4096]:add('rsa-bits-'+str(n),'cardKey',rsa(n),'PASS' if n in [2048,3072] else '78-CARD-KEY','boundary',['78-CARD-KEY','78-SPKI','78-RSA-EXPONENT'])
for e in [3,65536,65537,65539]:add('rsa-exponent-'+str(e),'cardKey',rsa(2048,e),'PASS' if e==65537 else '78-RSA-EXPONENT','boundary',['78-RSA-EXPONENT'])
add('rsa-negative-exponent','cardKey',rsa(2048,-1),'78-SPKI','malformed')
add('rsa-negative-modulus','cardKey',seq(alg(RSA,NULL),der(3,b'\0'+seq(integer(-1),integer(65537)))),'78-SPKI','malformed')
add('rsa-absent-parameters','cardKey',rsa(2048,p=b''),'78-SPKI','negative')
add('rsa-integer-parameters','cardKey',rsa(2048,p=integer(1)),'78-SPKI','negative')
p256=bytes.fromhex('04'+'6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'+'4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
p384=bytes.fromhex('04'+'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'+'3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f')
for name,curve,point in [('p256',P256,p256),('p384',P384,p384)]:add(name,'cardKey',ec(curve,point),rules=['78-CARD-KEY','78-SPKI'])
add('same-size-wrong-curve','cardKey',ec('1.3.132.0.10',p256),'78-CARD-KEY','negative')
add('ec-explicit-parameters','cardKey',ec(P256,p256,p=seq()),'78-SPKI','negative')
add('ec-invalid-point','cardKey',ec(P256,b'\x04'+b'\0'*64),'78-SPKI','malformed')
add('ec-infinity','cardKey',ec(P256,b'\0'),'78-SPKI','negative')
add('unsupported-key-algorithm','cardKey',seq(alg('1.2.840.10040.4.1'),der(3,b'\0\x01')),'78-SPKI','negative')
for o,label in [('1.2.840.113549.1.1.11','rsa256'),('1.2.840.113549.1.1.12','rsa384')]:
    for name,p in [('null',NULL),('absent',b''),('invalid',integer(1))]:add(label+'-'+name,'signatureAlgorithm',alg(o,p),'78-CERT-SIGNATURE' if name=='invalid' else 'PASS','negative' if name=='invalid' else 'positive',['78-CERT-SIGNATURE'])
for o,label in [('1.2.840.10045.4.3.2','ecdsa256'),('1.2.840.10045.4.3.3','ecdsa384')]:
    add(label,'signatureAlgorithm',alg(o),rules=['78-CERT-SIGNATURE'])
    add(label+'-null','signatureAlgorithm',alg(o,NULL),'78-CERT-SIGNATURE','negative')
for digest,label,salt in [(SHA256,'256',32),(SHA384,'384',48)]:
    params=seq(der(0xa0,alg(digest,NULL)),der(0xa1,alg('1.2.840.113549.1.1.8',alg(digest,NULL))),der(0xa2,integer(salt)))
    add('pss-'+label,'signatureAlgorithm',alg(PSS,params),rules=['78-CERT-SIGNATURE'])
add('pss-absent','signatureAlgorithm',alg(PSS),'78-CERT-SIGNATURE','malformed')
add('pss-sha1-default','signatureAlgorithm',alg(PSS,seq()),'78-CERT-SIGNATURE','negative')
add('pss-duplicate-hash','signatureAlgorithm',alg(PSS,seq(der(0xa0,alg(SHA256,NULL)),der(0xa0,alg(SHA384,NULL)))),'78-CERT-SIGNATURE','malformed')
add('pss-negative-salt','signatureAlgorithm',alg(PSS,seq(der(0xa0,alg(SHA256,NULL)),der(0xa2,integer(-1)))),'78-CERT-SIGNATURE','boundary')
add('pss-invalid-trailer','signatureAlgorithm',alg(PSS,seq(der(0xa0,alg(SHA256,NULL)),der(0xa3,integer(2)))),'78-CERT-SIGNATURE','negative')
add('pss-unknown-mgf-hash','signatureAlgorithm',alg(PSS,seq(der(0xa0,alg(SHA256,NULL)),der(0xa1,alg('1.2.840.113549.1.1.8',alg('1.2.3.4',NULL))))),'78-CERT-SIGNATURE','negative')
for o,name in [('1.2.840.113549.1.1.5','sha1'),('1.2.840.113549.1.1.13','sha512'),('1.2.3.4','unknown')]:add('signature-'+name,'signatureAlgorithm',alg(o,NULL),'78-CERT-SIGNATURE','negative')
for method,valid,rule in [('cardKey',rsa(2048),'78-SPKI'),('signatureAlgorithm',alg('1.2.840.113549.1.1.11',NULL),'78-CERT-SIGNATURE')]:
    for name,b in [('empty',b''),('truncated',valid[:-1]),('trailing',valid+b'\0'),('bad-length',b'\x30\x84\xff\xff\xff\xff')]:add(method+'-'+name,method,b,rule,'malformed')
dest=ROOT/'conformancelib/src/main/resources/standards/current-crypto.tsv'
dest.write_text('# id\tmethod\texpected-rule-or-PASS\thex\n'+''.join(f"{v['id']}\t{v['method']}\t{v['expected']}\t{v['input_hex']}\n" for v in vectors))
(ROOT/'standards/crypto-vectors.json').write_text(json.dumps(vectors,indent=2)+'\n')
print(len(vectors),'vectors',hashlib.sha256(dest.read_bytes()).hexdigest())
