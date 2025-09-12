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


def key_scram():
    """
    salts
    """

#to use
def setup():
    """
    the o'l init
    """
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

def get_master():
    """
    prompt master password
    """


def open_vault():
    """
    UNLOCK
    """
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
    #name
    #username
    #email? lata?
    #url
    #password, allow gen or custom
    s.set_defaults(func=term_add)


def main():
    parser = create_parser()



if __name__ == "__main__":
    main()