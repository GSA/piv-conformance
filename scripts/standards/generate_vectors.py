#!/usr/bin/env python3
"""Deterministic synthetic TLV vectors; values are artificial, not complete credentials.

Each vector isolates a structural assertion. Passing a structural vector does not
prove validity of its placeholder certificate, signature, FASC-N or key material.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT/'conformancelib/src/main/resources/standards/current-data-model.tsv'
vectors = []


def tlv(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x80+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([tag])+length+value


def obj(fields):
    return tlv(0x53,b''.join(tlv(t,v) for t,v in fields))


def add(id, method, fields, rule='PASS', kind='positive', requirements=None):
    data = fields if isinstance(fields,bytes) else obj(fields)
    vectors.append(dict(id=id,method=method,input_hex=data.hex(),expected=rule,kind=kind,
                        requirements=requirements or [rule],sha256=hashlib.sha256(data).hexdigest()))


ccc=[(t,b'\x10' if t==0xf5 else b'') for t in [0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xfa,0xfb,0xfc,0xfd,0xfe]]
add('ccc-zero-length-fields','ccc',ccc,requirements=['73-CCC-FIELDS'])
for tag in [0xe3,0xb4]: add(f'ccc-removed-{tag:x}','ccc',ccc[:-1]+[(tag,b'')]+ccc[-1:],'73-CCC-FIELDS','negative')
for tag,size in [(0xf0,20),(0xf1,2),(0xf3,129),(0xf5,0),(0xf6,16),(0xf7,1),(0xfe,1)]:
    add(f'ccc-bad-width-{tag:x}','ccc',[(t,b'\0'*size if t==tag else v) for t,v in ccc],'73-CCC-FIELDS','boundary')
add('ccc-cardurl-128','ccc',[(t,b'a'*128 if t==0xf3 else v) for t,v in ccc],kind='boundary',requirements=['73-CCC-FIELDS'])
add('ccc-wrong-data-model','ccc',[(t,b'\x11' if t==0xf5 else v) for t,v in ccc],'73-CCC-FIELDS','negative')

uuid=bytes.fromhex('00112233445546778899aabbccddeeff')
chuid=[(0x30,b'\0'*25),(0x34,uuid),(0x35,b'20280229'),(0x3e,b'\x01'),(0xfe,b'')]
chuid_rules=['73-CHUID-FIELDS','73-CARD-UUID','73-CHUID-DATE']
add('chuid-valid-leap-date','chuid',chuid,requirements=chuid_rules)
add('chuid-optional-holder','chuid',chuid[:3]+[(0x36,uuid)]+chuid[3:],requirements=chuid_rules+['73-HOLDER-UUID'])
for tag in [0xee,0x32,0x33,0x3d]: add(f'chuid-removed-{tag:x}','chuid',chuid[:-1]+[(tag,b'')]+chuid[-1:],'73-CHUID-FIELDS','negative')
for value,name in [(b'20270229','non-leap'),(b'20261301','month'),(b'20260931','day'),(b'2026x930','ascii'),(b'2026093','short')]:
    add('chuid-date-'+name,'chuid',[(t,value if t==0x35 else v) for t,v in chuid],'73-CHUID-DATE','boundary')
for ver in [1,4,5,0,2,3,6,7,8,15]:
    u=bytearray(uuid);u[6]=(u[6]&15)|(ver<<4)
    add(f'card-uuid-version-{ver}','chuid',[(t,bytes(u) if t==0x34 else v) for t,v in chuid], 'PASS' if ver in [1,4,5] else '73-CARD-UUID', 'positive' if ver in [1,4,5] else 'negative', ['73-CARD-UUID'])
for holder in [False,True]:
    for variant in [0,0x80,0xc0,0xe0]:
        u=bytearray(uuid);u[8]=variant
        f=chuid[:3]+[(0x36,bytes(u))]+chuid[3:] if holder else [(t,bytes(u) if t==0x34 else v) for t,v in chuid]
        rule='73-HOLDER-UUID' if holder else '73-CARD-UUID'
        add(f'uuid-variant-{holder}-{variant}','chuid',f,'PASS' if variant==0x80 else rule,'boundary',[rule])
    for size in [15,17]:
        u=(uuid+b'\0')[:size]
        f=chuid[:3]+[(0x36,u)]+chuid[3:] if holder else [(t,u if t==0x34 else v) for t,v in chuid]
        add(f'uuid-width-{holder}-{size}','chuid',f,'73-HOLDER-UUID' if holder else '73-CARD-UUID','boundary')
u=bytearray(uuid);u[6]=0x10
add('holder-v1-disallowed','chuid',chuid[:3]+[(0x36,bytes(u))]+chuid[3:],'73-HOLDER-UUID','negative')
for size in [2816,2817]:
    add(f'chuid-signature-{size}','chuid',[(t,b'\0'*size if t==0x3e else v) for t,v in chuid], 'PASS' if size==2816 else '73-CHUID-FIELDS','boundary',['73-CHUID-FIELDS'])

cert=[(0x70,b'\0'*1856),(0x71,b'\0'),(0xfe,b'')]
for size in [1855,1856,1857,4096]: add(f'certificate-size-{size}','certificateObject',[(0x70,b'\0'*size)]+cert[1:],kind='boundary',requirements=['73-CERT-SIZE','73-CERT-FIELDS'])
for info in [0,1,2,4,128,255]: add(f'certinfo-{info}','certificateObject',[(0x70,b'\0'),(0x71,bytes([info])),(0xfe,b'')],'PASS' if info<2 else '73-CERT-FIELDS','positive' if info<2 else 'negative',['73-CERT-FIELDS'])
add('certificate-removed-mscuid','certificateObject',cert[:-1]+[(0x72,b'')]+cert[-1:],'73-CERT-FIELDS','negative')
so=[(0xba,b'\x01\xdb\x00'),(0xbb,b'\x01'),(0xfe,b'')]
add('security-mapping-triple','securityObject',so,requirements=['73-SECURITY-FIELDS'])
add('security-short-mapping','securityObject',[(0xba,b'\x01\xdb')]+so[1:],'73-SECURITY-FIELDS','malformed')
for size in (27,30,33):
    add(f'security-mapping-{size}','securityObject',[(0xba,b'\x01\xdb\x00'*(size//3))]+so[1:],
        'PASS' if size<=30 else '73-SECURITY-FIELDS','boundary',['73-SECURITY-FIELDS'])
for size in (1297,1298,1299):
    add(f'security-value-{size}','securityObject',[so[0],(0xbb,b'\x01'*size),so[2]],
        'PASS' if size<=1298 else '73-SECURITY-FIELDS','boundary',['73-SECURITY-FIELDS'])
retired=[(0x70,b'\x01'),(0x71,b'\0'),(0xfe,b'')]
add('retired-no-mscuid','retiredCertificateObject',retired,requirements=['73-RETIRED-CERT-FIELDS'])
for size in (0,37,38,39):
    add(f'retired-mscuid-{size}','retiredCertificateObject',retired[:-1]+[(0x72,b'A'*size)]+retired[-1:],
        'PASS' if size<=38 else '73-RETIRED-CERT-FIELDS','boundary',['73-RETIRED-CERT-FIELDS'])
for value in (1,2,255):
    add(f'retired-certinfo-{value}','retiredCertificateObject',[retired[0],(0x71,bytes([value])),retired[2]],
        'PASS' if value==1 else '73-RETIRED-CERT-FIELDS','negative' if value!=1 else 'positive',['73-RETIRED-CERT-FIELDS'])
printed=[(1,b'Synthetic'),(2,b'Test'),(4,b'2028FEB29'),(5,b'0000'),(6,b'TESTONLY'+b' '*7),(0xfe,b'')]
add('printed-valid','printedInformation',printed,requirements=['73-PRINTED-FIELDS'])
add('printed-optional-lines','printedInformation',printed[:-1]+[(7,b'Test'),(8,b'Test')]+printed[-1:],requirements=['73-PRINTED-FIELDS'])
for tag,limit in ((1,125),(2,20),(5,20),(6,15)):
    for size in (limit,limit+1):
        add(f'printed-length-{tag}-{size}','printedInformation',[(t,b'A'*size if t==tag else v) for t,v in printed],
            'PASS' if size==limit else '73-PRINTED-FIELDS','boundary',['73-PRINTED-FIELDS'])
for date in (b'2027FEB29',b'2028XYZ29',b'2028FEB2'):
    add('printed-date-'+date.decode(),'printedInformation',[(t,date if t==4 else v) for t,v in printed],'73-PRINTED-FIELDS','boundary')
add('printed-non-ascii','printedInformation',[(t,b'\xff' if t==1 else v) for t,v in printed],'73-PRINTED-FIELDS','negative')
add('printed-issuer-short','printedInformation',[(t,b'A'*14 if t==6 else v) for t,v in printed],'73-PRINTED-FIELDS','boundary')
pairing=[(0x99,b'01234567'),(0xfe,b'')]
add('pairing-valid','pairingCode',pairing,requirements=['73-PAIRING-FIELDS'])
for value,name in ((b'0123456','short'),(b'012345678','long'),(b'0123456a','letter'),(b'0123456\xff','non-ascii')):
    add('pairing-'+name,'pairingCode',[(0x99,value),(0xfe,b'')],'73-PAIRING-FIELDS','boundary' if name in ('short','long') else 'negative')
for method,f,rule in [('retiredCertificateObject',retired,'73-RETIRED-CERT-FIELDS'),('printedInformation',printed,'73-PRINTED-FIELDS'),('pairingCode',pairing,'73-PAIRING-FIELDS')]:
    add(method+'-missing',method,f[1:],rule,'negative')
    add(method+'-duplicate',method,f[:1]+f,rule,'negative')
    add(method+'-wrong-order',method,list(reversed(f)),rule,'negative')
    add(method+'-truncated',method,obj(f)[:-1],rule,'malformed')
    add(method+'-indefinite',method,b'\x53\x80\x00\x00',rule,'malformed')
url=b'http://example.invalid/'+b'a'*64
for on,off,has_url,ok in [(0,0,False,True),(0,0,True,False),(1,0,False,True),(1,0,True,True),(0,1,False,False),(0,1,True,True),(20,0,False,True),(20,1,True,False),(0,20,True,True),(255,0,False,False)]:
    f=[(0xc1,bytes([on])),(0xc2,bytes([off]))]+([(0xf3,url)] if has_url else [])+[(0xfe,b'')]
    add(f'history-{on}-{off}-{has_url}','keyHistory',f,'PASS' if ok else '73-KEY-HISTORY','conditional',['73-KEY-HISTORY'])
for name,value in [('https',url.replace(b'http:',b'https:')),('short-hash',url[:-1]),('non-hex',url[:-1]+b'z'),('long',b'http://'+b'a'*48+b'/'+b'0'*64),('empty-label',url.replace(b'example.invalid',b'example..invalid')),('hyphen-label',url.replace(b'example.invalid',b'example-.invalid'))]:
    add('history-url-'+name,'keyHistory',[(0xc1,b'\0'),(0xc2,b'\1'),(0xf3,value),(0xfe,b'')],'73-KEY-HISTORY','boundary')
add('history-absolute-dns','keyHistory',[(0xc1,b'\0'),(0xc2,b'\1'),(0xf3,url.replace(b'example.invalid/',b'example.invalid./')),(0xfe,b'')],requirements=['73-KEY-HISTORY'])

for method,f,rule in [('ccc',ccc,'73-CCC-FIELDS'),('chuid',chuid,'73-CHUID-FIELDS'),('certificateObject',cert,'73-CERT-FIELDS'),('securityObject',so,'73-SECURITY-FIELDS'),('keyHistory',[(0xc1,b'\0'),(0xc2,b'\0'),(0xfe,b'')],'73-KEY-HISTORY')]:
    add(method+'-missing-mandatory',method,f[1:],rule,'negative')
    add(method+'-duplicate',method,f[:1]+f,rule,'negative')
    add(method+'-wrong-order',method,list(reversed(f)),rule,'negative')
    for name,raw in [('truncated',obj(f)[:-1]),('indefinite',b'\x53\x80\x00\x00'),('length-overflow',b'\x53\x84\xff\xff\xff\xff'),('missing-length',b'\x53'),('trailing',obj(f)+b'\xfe\x00')]:
        add(method+'-'+name,method,raw,rule,'malformed')
DEST.parent.mkdir(parents=True,exist_ok=True)
DEST.write_text('# id\tmethod\texpected-rule-or-PASS\thex\n'+''.join(f"{v['id']}\t{v['method']}\t{v['expected']}\t{v['input_hex']}\n" for v in vectors))
(ROOT/'standards/data-model-vectors.json').write_text(json.dumps(vectors,indent=2)+'\n')
print(len(vectors),'vectors',hashlib.sha256(DEST.read_bytes()).hexdigest())
