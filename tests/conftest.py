"""Shared pytest fixtures for all test modules."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Add service source paths to PYTHONPATH
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "services" / "api" / "src"))
sys.path.insert(0, str(repo_root / "services" / "agent-runtime" / "src"))
sys.path.insert(0, str(repo_root / "services" / "rag-core" / "src"))

# Set test environment defaults
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-chars-minimum-xx")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test_db")
os.environ.setdefault("AZURE_OPENAI_ENDPOINT", "")
os.environ.setdefault("AZURE_OPENAI_API_KEY", "")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "10000")
os.environ.setdefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")


@pytest.fixture
def vulnerable_python_sql_injection() -> str:
    """Python code with SQL injection vulnerability."""
    return """
import sqlite3

def get_user(db, username: str):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = db.cursor()
    return cursor.execute(query)
"""


@pytest.fixture
def vulnerable_python_command_injection() -> str:
    """Python code with command injection vulnerability."""
    return """
import subprocess

def run_command(user_input: str):
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout
"""


@pytest.fixture
def vulnerable_python_eval() -> str:
    """Python code with eval() code injection."""
    return """
def calculate(expression: str):
    return eval(expression)
"""


@pytest.fixture
def vulnerable_python_pickle() -> str:
    """Python code with insecure deserialization."""
    return """
import pickle
import base64

def load_session(session_data: str):
    decoded = base64.b64decode(session_data)
    return pickle.loads(decoded)
"""


@pytest.fixture
def vulnerable_python_weak_crypto() -> str:
    """Python code with weak cryptographic hash."""
    return """
import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
"""


@pytest.fixture
def safe_python_code() -> str:
    """Python code without known security vulnerabilities."""
    return """
import hashlib
import secrets

def create_token() -> str:
    return secrets.token_urlsafe(32)

def hash_value(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def get_user(db, username: str):
    query = "SELECT * FROM users WHERE username = ?"
    cursor = db.cursor()
    return cursor.execute(query, (username,))
"""
