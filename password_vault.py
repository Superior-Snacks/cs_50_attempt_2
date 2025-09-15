import base64
import json
import os
import sys
import getpass
import argparse
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_PATH = os.path.join(VAULT_DIR, "vault.json")
DEFAULT_ITERATIONS = 200_000


def b64e(b):
    return base64.b64encode(b).decode("ascii")


def b64d(s):
    return base64.b64decode(s.encode("ascii"))


def key_scram(master, salt, DEFAULT_ITERATIONS):
    return hashlib.pbkdf2_hmac("sha256", master.encode("utf-8"), salt, DEFAULT_ITERATIONS, dklen=32)


def get_master():
    return getpass.getpass("Master password: ")


def setup(args):
    if os.path.exists(VAULT_PATH):
        sys.exit(1)
    master = get_master()
    if not master:
        print("MASTER PASS REQUIERD")
        sys.exit(1)
    salt = secrets.token_bytes(16)
    key = key_scram(master, salt, DEFAULT_ITERATIONS)
    entrys = []
    cypher = encrypt(key, entrys)

    vault = {
        "version": 1,
        "scram" : {"salt_b64e":b64e(salt), "iterations": DEFAULT_ITERATIONS},
        "cipher": cypher,
    }
    write_vault(VAULT_PATH, vault)
    print(f"created vault {VAULT_PATH}")


def encrypt(key, val):
    iv = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(val).encode("utf-8")
    ct = aesgcm.encrypt(iv, plaintext, None)
    return {
        "iv": b64e(iv),
        "ciphertext": b64e(ct)
    }


def decrypt(key, iv_str, ct_str):
    iv = b64d(iv_str)
    ct = b64d(ct_str)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(iv, ct, None)
    return json.loads(pt.decode("utf-8"))


def read_vault(p):
    if not os.path.exists(p):
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)
    

def write_vault(p, data):
    with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def open_vault(master, vault_data):
    #check if data
    salt_b = vault_data["scram"]["salt_b64e"]
    iterations = int(vault_data["scram"]["iterations"])
    key = key_scram(master, b64d(salt_b), iterations)
    entries = decrypt(key,
        vault_data["cipher"]["iv"],
        vault_data["cipher"]["ciphertext"]
        )
    return entries, key, vault_data


def save_to_vault(entries, key, vault_data):
    cipher = encrypt(key, entries)
    vault_data["cipher"] = cipher
    write_vault(VAULT_PATH, vault_data)


def term_list(args):
    master = get_master()
    vault_data = read_vault(VAULT_PATH)
    entries, key, meta = open_vault(master, vault_data)
    if not entries:
        return print("foo, no entrys, that check out?... seems bad")
    for i in entries:
        print(f"name:{i['name']}, username:{i['username']}, email:{i['email']}, url:{i['url']}")


def term_add(args):
    master = get_master()
    vault_data = read_vault(VAULT_PATH)
    entries, key, meta = open_vault(master, vault_data)
    new_entry = {
        "id": secrets.token_hex(16),
        "name": args.name.strip(),
        "username": args.username.strip(),
        "email": (args.email or "").strip(),
        "url": (args.url or "").strip(),
        "password": args.password if args.password else "changeme123!"
    }
    entries.append(new_entry)
    save_to_vault(entries, key, meta)
    print(f"Added '{new_entry['name']}'.")


def term_delete(args):
    master = get_master()
    vault_data = read_vault(VAULT_PATH)
    entries, key, meta = open_vault(master, vault_data)

    found = []
    for i in entries:
        if (args.id == i["id"]) or (args.name == i["name"]):
            found.append(i)
    if not found:
        print("entry to delete not found")
        sys.exit(1)


def term_show(args):
    master = get_master()
    vault_data = read_vault(VAULT_PATH)
    entries, key, meta = open_vault(master, vault_data)

    found = False
    for i in entries:
        if (args.id == i["id"]) or (args.name == i["name"]):
            print(json.dumps(i, indent=2))
            found = True
    if not found:
        print("entry not found")
        sys.exit(1)


def create_parser():
    p = argparse.ArgumentParser(description="MY PASSWORD MANAGER")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="Create new vault.")
    s.set_defaults(func=setup)

    s = sub.add_parser("list", help="List entries.")
    s.set_defaults(func=term_list)

    s = sub.add_parser("add", help="add new wntry")
    s.add_argument("--name", required=True)
    s.add_argument("--username", required=True)
    s.add_argument("--email", default="")
    s.add_argument("--url", default="")
    s.add_argument("--password", help="laev blanc for gen")
    s.set_defaults(func=term_add)

    s = sub.add_parser("show", help="Show entry")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--name")
    g.add_argument("--id")
    s.set_defaults(func=term_show)

    return p


def main(argv=None):
    parser = create_parser()
    args = parser.parse_args(argv)
    args.func(args)
if __name__ == "__main__":
    main()