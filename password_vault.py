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

#to use
def setup():
    ...

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

def open_vault():
    ...
def save_to_vault():
    ...

def term_add():
    ...
def term_show():
    ...






def main():
    ...

if __name__ == "__main__":
    main()