#!/usr/bin/env python3
"""Regenerate the synthetic public certificates and verify committed hashes.

Requires JAVA_HOME pointing to Java 17 and cached BC 1.66 Maven artifacts.
No private keys are written. Output stays under conformancelib/build.
"""
from pathlib import Path
import os
import subprocess

ROOT=Path(__file__).resolve().parents[2]
jdk=Path(os.environ['JAVA_HOME'])/'bin'
work=ROOT/'conformancelib/build/synthetic-corpus-generation'
work.mkdir(parents=True,exist_ok=True)
cache=Path(os.environ.get('GRADLE_USER_HOME',str(Path.home()/'.gradle')))/'caches/modules-2/files-2.1/org.bouncycastle'
jars=[next((cache/name/'1.66').glob('*/*.jar')) for name in ('bcprov-jdk15on','bcpkix-jdk15on')]
cp=os.pathsep.join(map(str,jars))
subprocess.run([str(jdk/'javac'),'-cp',cp,'-d',str(work),str(ROOT/'scripts/standards/SyntheticCertificateCorpus.java')],check=True)
dest=work/'certificates'
subprocess.run([str(jdk/'java'),'-cp',str(work)+os.pathsep+cp,'SyntheticCertificateCorpus',str(dest)],check=True)
expected=ROOT/'conformancelib/src/main/resources/standards/synthetic-certificates'
for p in expected.iterdir():
    assert p.read_bytes()==(dest/p.name).read_bytes(),f'Generation drift: {p.name}'
print('Synthetic certificate regeneration matches every committed byte.')
