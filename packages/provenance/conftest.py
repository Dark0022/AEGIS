"""Shared pytest fixtures for AEGIS provenance tests."""

from __future__ import annotations

import getpass

import pytest


@pytest.fixture(scope="session")
def issuer_v7_password() -> str:
    """Prompt once for the current AEGIS Issuer v7 password."""
    return getpass.getpass(
        "Enter the Emergency Communications Issuer v7 password: "
    )