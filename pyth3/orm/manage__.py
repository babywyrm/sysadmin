#!/usr/bin/env python3

"""
manage.py

Simple CLI to create (or drop & recreate) all tables defined
in models.py.
"""
import sys
from models import db, ALL_MODELS

def create():
    db.connect()
    db.create_tables(ALL_MODELS)
    print("✔ Tables created")

def drop():
    db.connect()
    db.drop_tables(ALL_MODELS)
    print("✔ Tables dropped")

def recreate():
    drop()
    create()

if __name__ == "__main__":
    # usage: manage.py [create|drop|recreate]
    cmd = sys.argv[1] if len(sys.argv) > 1 else "create"
    if cmd == "create":
        create()
    elif cmd == "drop":
        drop()
    elif cmd == "recreate":
        recreate()
    else:
        print(f"Unknown command '{cmd}'.  Use create|drop|recreate.")
        sys.exit(1)
      
##
##
