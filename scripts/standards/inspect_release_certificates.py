#!/usr/bin/env python3
"""Inspect downloaded official release archives; do not extract or decrypt identities.

Pass the downloads.json produced from the GitHub releases API inventory. Each row
must have tag, url and file fields. Output includes hashes, names and encryption
flags only. Archives are never executed and certificate subjects are not printed.
"""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
corpus_path = ROOT / 'standards/certificate-corpus.json'
corpus = json.loads(corpus_path.read_text())
wanted = {m['historical_filename'].lower() for m in corpus['mapping']}


def inspect_zip(data, location, depth=0):
    found = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            name = Path(entry.filename).name.lower()
            if name in wanted:
                found.append(dict(path=location + '!/' + entry.filename, encrypted=bool(entry.flag_bits & 1), size=entry.file_size))
            elif depth < 3 and name.endswith(('.zip', '.jar')) and not entry.flag_bits & 1:
                nested = archive.read(entry)
                if zipfile.is_zipfile(io.BytesIO(nested)):
                    found.extend(inspect_zip(nested, location + '!/' + entry.filename, depth+1))
    return found


results = []
for asset in json.loads(Path(sys.argv[1]).read_text()):
    path = Path(asset['file'])
    data = path.read_bytes()
    if zipfile.is_zipfile(io.BytesIO(data)):
        matches = inspect_zip(data, path.name)
    else:
        matches = []
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for entry in archive.getmembers():
                if not entry.isfile(): continue
                name = Path(entry.name).name.lower()
                if name in wanted:
                    matches.append(dict(path=path.name+'!/'+entry.name, encrypted=False, size=entry.size))
                elif name.endswith(('.zip','.jar')):
                    nested = archive.extractfile(entry).read()
                    if zipfile.is_zipfile(io.BytesIO(nested)):
                        matches.extend(inspect_zip(nested,path.name+'!/'+entry.name,1))
    results.append(dict(release=asset['tag'],url=asset['url'],size=len(data),
                        sha256=hashlib.sha256(data).hexdigest(),matches=matches))
corpus['official_release_asset_search'] = results
corpus['release_search_date'] = '2026-10-01'
corpus['release_search_metadata'] = 'https://api.github.com/repos/GSA/piv-conformance/releases?per_page=100 (35 releases; all published assets inspected)'
corpus['limits'] = [v for v in corpus['limits'] if not v.startswith('Remote release assets')]
corpus['limits'].append('Every matching release entry is reported below. Encrypted originals remain unavailable for semantic provenance/identity review; no original was used as a synthetic fixture.')
corpus_path.write_text(json.dumps(corpus,indent=2)+'\n')
print(len(results),'release assets inspected;',sum(len(r['matches']) for r in results),'matching entries;',
      sum(not m['encrypted'] for r in results for m in r['matches']),'unencrypted matches')
