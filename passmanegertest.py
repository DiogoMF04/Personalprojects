


# tests/test_password_manager.py
import os
import pytest
from tools import password_manager as pm

TEST_DB = "test_vault.db"

@pytest.fixture(autouse=True)
def cleanup():
    # Clean before and after each test
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    yield
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

def test_init_and_load():
    key = pm.init_db(TEST_DB, "master123")
    assert isinstance(key, bytes)
    key2 = pm.load_key(TEST_DB, "master123")
    assert key == key2

def test_wrong_master_password():
    pm.init_db(TEST_DB, "goodpass")
    with pytest.raises(Exception):
        pm.load_key(TEST_DB, "badpass")

def test_add_and_get_entry():
    key = pm.init_db(TEST_DB, "master")
    pm.add_entry(TEST_DB, key, "gmail", "alice", "secretpw")
    user, pwd = pm.get_entry(TEST_DB, key, "gmail")
    assert user == "alice"
    assert pwd == "secretpw"

def test_duplicate_entry_overwrites():
    key = pm.init_db(TEST_DB, "master")
    pm.add_entry(TEST_DB, key, "github", "bob", "firstpw")
    pm.add_entry(TEST_DB, key, "github", "bob", "newpw")
    _, pwd = pm.get_entry(TEST_DB, key, "github")
    assert pwd == "newpw"  # last one wins

def test_nonexistent_entry():
    key = pm.init_db(TEST_DB, "master")
    result = pm.get_entry(TEST_DB, key, "noservice")
    assert result is None

def test_delete_entry():
    key = pm.init_db(TEST_DB, "master")
    pm.add_entry(TEST_DB, key, "slack", "alice", "pw")
    assert pm.get_entry(TEST_DB, key, "slack") is not None
    pm.delete_entry(TEST_DB, key, "slack")
    assert pm.get_entry(TEST_DB, key, "slack") is None

def test_empty_service_name():
    key = pm.init_db(TEST_DB, "master")
    with pytest.raises(ValueError):
        pm.add_entry(TEST_DB, key, "", "bob", "pw")

def test_long_passwords():
    key = pm.init_db(TEST_DB, "master")
    long_pw = "X" * 5000
    pm.add_entry(TEST_DB, key, "longpw", "bob", long_pw)
    _, pw = pm.get_entry(TEST_DB, key, "longpw")
    assert pw == long_pw

def test_corrupted_db():
    # Create a corrupted DB file
    with open(TEST_DB, "wb") as f:
        f.write(b"not a real db")
    with pytest.raises(Exception):
        pm.load_key(TEST_DB, "whatever")
