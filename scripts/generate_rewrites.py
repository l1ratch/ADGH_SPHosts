import requests
import yaml
import json
import os
from datetime import datetime

URL = "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/master/hosts"

OUT_FILE = "rewrites/rlist.txt"
OLD_FILE = "rewrites/rewrites_old.json"
LOG_DIR = "rewrites/logs"


def fetch():
    return requests.get(URL, timeout=15).text.splitlines()


def parse(lines):
    rewrites = []
    start = False

    for line in lines:
        line = line.strip()

        if line.startswith("### dns.malw.link"):
            start = True
            continue

        if line.startswith("# Блокировка"):
            break

        if not start or not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        ip, domain = parts[0], parts[1]

        if ip.startswith("0.0.0.0"):
            continue

        rewrites.append({
            "domain": domain,
            "answer": ip,
            "enabled": True
        })

    # remove duplicates
    uniq = {}
    for r in rewrites:
        uniq[(r["domain"], r["answer"])] = r

    return list(uniq.values())


def load_old():
    if not os.path.exists(OLD_FILE):
        return []
    with open(OLD_FILE, "r") as f:
        return json.load(f)


def save_old(data):
    with open(OLD_FILE, "w") as f:
        json.dump(data, f, indent=2)


def diff(old, new):
    old_set = {(x["domain"], x["answer"]) for x in old}
    new_set = {(x["domain"], x["answer"]) for x in new}

    return new_set - old_set, old_set - new_set


def write_log(added, removed):
    os.makedirs(LOG_DIR, exist_ok=True)
    path = f"{LOG_DIR}/{datetime.now().date()}.log"

    with open(path, "a") as f:
        f.write(f"\n[{datetime.now()}]\n")

        for d, ip in sorted(added):
            f.write(f"[+] {d} -> {ip}\n")

        for d, ip in sorted(removed):
            f.write(f"[-] {d} -> {ip}\n")


def write_yaml(data):
    out = {
        "filtering": {
            "rewrites": data
        }
    }

    with open(OUT_FILE, "w") as f:
        yaml.dump(out, f, allow_unicode=True, sort_keys=False)


def main():
    lines = fetch()
    new = parse(lines)
    old = load_old()

    added, removed = diff(old, new)

    write_yaml(new)
    save_old(new)
    write_log(added, removed)

    print(f"Added: {len(added)}, Removed: {len(removed)}")


if __name__ == "__main__":
    main()
