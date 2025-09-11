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
    ...
#less safe
def decrypt():
    ...

#open n close
def read_vault():
    ...
def write_vault():
    ...


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