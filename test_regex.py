import urllib.request, zipfile, io, re
r = urllib.request.urlopen('https://cwe.mitre.org/data/csv/1000.csv.zip')
z = zipfile.ZipFile(io.BytesIO(r.read()))
lines = z.open(z.namelist()[0]).read().decode('utf-8', errors='replace').splitlines()
header_idx = -1
for idx, line in enumerate(lines):
    if line.startswith('CWE-ID'):
        header_idx = idx
        break

print('header_idx:', header_idx)
version = "Unknown"
for i in range(header_idx):
    version_match = re.search(r"Version\s+([\d\.]+)", lines[i])
    print(repr(lines[i]))
    if version_match:
        version = version_match.group(1)
        print("MATCHED:", version)
        break
print(version)
