"""Intentional examples for local VulnFusion smoke testing only."""

import os
import sqlite3


def search_user(keyword: str):
    db = sqlite3.connect(":memory:")
    query = f"SELECT * FROM users WHERE name = '{keyword}'"
    return db.execute(query).fetchall()


def run_tool(command: str):
    return os.system(command)
