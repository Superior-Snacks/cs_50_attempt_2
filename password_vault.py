import base64
import json
import os
import sys
import getpass
import argparse
import hashlib
import secrets
import cryptography

VAULT_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_PATH = os.path.join(VAULT_DIR, "vault.json")
DEFAULT_ITERATIONS = 200_000

#a lil help
def b64e(b):
    return base64.b64encode(b).decode("ascii")

def b64d(s):
    return base64.b64decode(s.encode("ascii"))


def key_scram(master, salt, DEFAULT_ITERATIONS):
    """
    salts
    """

def get_master():
    return getpass.getpass("Master password: ")

#to use
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
        "scram" : {"salt_b64d":b64d(salt), "iterations": DEFAULT_ITERATIONS},
        "cipher": cypher,
    }
    write_vault(VAULT_PATH, vault)
    print(f"created vault {VAULT_PATH}")



# make it safe
def encrypt():
    """
    by the book do not be brave young cunt
    """
#less safe
def decrypt():
    """
    ======II=======
    """

#open n close
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
    salt_b = vault_data["scarm"]["saltb64d"]
    iterations = int(vault_data["scram"]["iterations"])



def save_to_vault():
    """
    save enrtys
    """

def term_list():
    """
    """

def term_add():
    """
    """

def term_show():
    """
    
    """

def create_parser():
    p = argparse.ArgumentParser(description="MY PASSWORD MANAGER")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="Create new vault.")
    s.set_defaults(func=setup)

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