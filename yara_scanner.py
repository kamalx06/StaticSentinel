import os
import sys
import yara
import math
import hashlib
import subprocess
import argparse
import requests
from collections import Counter

DEFAULT = "yara_rules"
REPO = "https://github.com/Yara-Rules/rules.git"
ENTROPY_MAX = 7
API = "https://www.virustotal.com/api/v3/files/"
API_KEY = "bd3aa5c0eb1a53d5493596925080eaeea9c103eb820c70d7a2e7b6eebcaf8c37"

def sha256_file(path):
    h256 = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            h256.update(chunk)
    return h256.hexdigest()

def entropy_calc(path):
    with open(path, "rb") as file:
        data = file.read()
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    for c in freq:
        if c == 0:
            continue
        p = c / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def virustotal_lookup(sha256):
    if not API_KEY:
        return None
    headers = {"x-apikey": API_KEY}
    resp = requests.get(API + sha256, headers=headers)
    if resp.status_code == 404:
        return {"found": False}
    if resp.status_code != 200:
        return {"error": resp.status_code}
    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }

def get_rules(rules_dir, update=True):
    if not os.path.isdir(rules_dir):
        print("Downloading YARA rules")
        subprocess.run(["git", "clone", REPO, rules_dir], check=True)

def load_rules(rules_dir):
    rule_files = {}
    skipped = []
    compiled = []
    for root, _, files in os.walk(rules_dir):
        for f in files:
            if f.endswith((".yar", ".yara")):
                path = os.path.join(root, f)
                rule_files[path] = path
    print(f"Attempting to compile {len(rule_files)} YARA files")
    for path in rule_files:
        try:
            rules = yara.compile(filepath=path)
            compiled.append(path)
        except yara.SyntaxError as e:
            skipped.append((path, str(e)))
    if not compiled:
        print("No valid YARA rules compiled")
        sys.exit(1)
    print(f"Compiled {len(compiled)} rules successfully")
    print(f"Skipped {len(skipped)} invalid rules")
    return yara.compile(filepaths={p: p for p in compiled})

def analyze_file(rules, path):
    size = os.path.getsize(path)
    sha256 = sha256_file(path)
    entropy = entropy_calc(path)
    packed = entropy > ENTROPY_MAX
    matches = rules.match(path)
    families = Counter(m.meta.get("family", "unknown") for m in matches)
    vt = virustotal_lookup(sha256)
    score = 0
    for m in matches:
        if "malware" in m.tags:
            score += 2
        if m.meta.get("family"):
            score += 3
    if packed:
        score += 2
    if vt and vt.get("found") and vt.get("malicious", 0) >= 5:
        score = max(score, 90)
    score = min(score * 10, 100)
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
    return {
        "path": path,
        "size": size,
        "sha256": sha256,
        "entropy": entropy,
        "packed": packed,
        "score": score,
        "verdict": verdict,
        "families": families,
        "matches": matches,
        "vt": vt
    }

def collect_files(target):
    if os.path.isfile(target):
        return [target]
    files = []
    for root, _, fs in os.walk(target):
        for f in fs:
            files.append(os.path.join(root, f))
    return files

def print_result(r):
    print(f"\nFile        : {r['path']}")
    print(f"Size        : {r['size']} bytes")
    print(f"SHA256      : {r['sha256']}")
    print(f"Entropy     : {r['entropy']} {'(Packed)' if r['packed'] else ''}")
    print(f"Score       : {r['score']} / 100")
    print(f"Verdict     : {r['verdict']}")
    if r["vt"]:
        if r["vt"].get("found"):
            print("VirusTotal  : "
                  f"{r['vt']['malicious']} malicious / "
                  f"{r['vt']['suspicious']} suspicious")
        else:
            print("VirusTotal  : Not found")
    if r["families"]:
        print("Families    :")
        for fam, cnt in r["families"].items():
            print(f"  - {fam}: {cnt} rule(s)")
    if r["matches"]:
        print("Matched YARA Rules:")
        for m in r["matches"]:
            print(f"  - {m.rule}")

def main():
    parser = argparse.ArgumentParser(description="Yara scanner by kamalx06")
    parser.add_argument("target", help="File or directory")
    parser.add_argument("--rules-dir", default=DEFAULT)
    args = parser.parse_args()
    if not API_KEY:
        print("Virustotal API Key not set")
        sys.exit(1)
    get_rules(args.rules_dir)
    rules = load_rules(args.rules_dir)
    files = collect_files(args.target)
    print(f"Scanning {len(files)} file")
    for file in files:
        try:
            result = analyze_file(rules, file)
            print_result(result)
        except Exception as e:
            print(f"Error scanning {file}: {e}")

if __name__ == "__main__":
    main()
