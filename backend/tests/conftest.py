"""Shared test setup. pytest runs this file automatically before the tests in this folder.

The cache keeps answers between lookups, which would let one test see another test's
answers. This empties it before every test, so each test starts from nothing.
"""
import pytest

import cache


# autouse=True: applied to every test without the test asking for it.
@pytest.fixture(autouse=True)
def empty_cache():
    cache.clear()
