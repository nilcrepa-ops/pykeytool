#!/usr/bin/env python3
"""Keystore access.

This is the high-level API used by the CLI. The PKCS#12 format itself is handled
by `core.pkcs12`, which supports any number of entries.

Unlike the earlier implementation -- which could only ever hold one key and
truncated the file on every write -- every operation here is read-modify-write
over the whole store, so adding or deleting one entry leaves the others alone.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from . import pkcs12
from .errors import KeytoolError
from .pkcs12 import Pkcs12Entry as Entry  # re-exported for callers

KEYSTORE_TYPE = "PKCS12"

#: keytool's own wording, kept so scripts that grep for it keep working.
WRONG_PASSWORD_MESSAGE = pkcs12.WRONG_PASSWORD_MESSAGE

__all__ = [
    "Entry",
    "Keystore",
    "KEYSTORE_TYPE",
    "WRONG_PASSWORD_MESSAGE",
    "load_keystore",
    "add_entry",
    "delete_entry",
    "ensure_alias_available",
    "store_exists",
]


@dataclass
class Keystore:
    """The parsed contents of a PKCS#12 file."""

    path: str
    password: str
    entries: list[Entry] = field(default_factory=list)
    #: SafeBags we do not model; re-emitted unchanged when the store is saved.
    preserved_bags: list[bytes] = field(default_factory=list)

    def find(self, alias: Optional[str]) -> Entry:
        """Look an entry up by alias (keytool aliases are case-insensitive)."""
        if not self.entries:
            raise KeytoolError(f"Keystore {self.path} does not contain any entries")

        if alias is None:
            return self.entries[0]

        wanted = alias.casefold()
        for entry in self.entries:
            if entry.alias is not None and entry.alias.casefold() == wanted:
                return entry

        available = ", ".join(sorted(e.alias or "<unnamed>" for e in self.entries))
        raise KeytoolError(
            f"Alias <{alias}> does not exist in {self.path} (available: {available})"
        )

    def alias_taken(self, alias: str) -> bool:
        wanted = alias.casefold()
        return any(e.alias is not None and e.alias.casefold() == wanted for e in self.entries)


def store_exists(path: str) -> bool:
    return os.path.exists(path) and os.path.getsize(path) > 0


def load_keystore(path: str, password: str) -> Keystore:
    """Read every entry in a PKCS#12 keystore."""
    if not os.path.exists(path):
        raise KeytoolError(f"Keystore file does not exist: {path}")
    if os.path.getsize(path) == 0:
        raise KeytoolError(f"Keystore file exists but is empty: {path}")

    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise KeytoolError(f"Can't read keystore {path}: {error.strerror}") from error

    parsed = pkcs12.load(data, password)
    return Keystore(
        path=path,
        password=password,
        entries=parsed.entries,
        preserved_bags=parsed.preserved_bags,
    )


def _write(store: Keystore) -> None:
    pkcs12.write(store.path, store.entries, store.password, store.preserved_bags)


def ensure_alias_available(path: str, alias: str, password: str, subject: str = "Key pair") -> None:
    """Fail *before* doing expensive work when the alias is already taken.

    keytool's wording is mirrored here::

        keytool error: Key pair not generated, alias <alice> already exists
    """
    if not store_exists(path):
        return

    store = load_keystore(path, password)
    if store.alias_taken(alias):
        raise KeytoolError(f"{subject} not generated, alias <{alias}> already exists")


def add_entry(path: str, entry: Entry, password: str, replace: bool = False) -> None:
    """Add an entry, preserving every entry already in the store.

    Creates the store when it does not exist yet. With ``replace=False`` an
    existing alias is refused, matching keytool.
    """
    if store_exists(path):
        store = load_keystore(path, password)
    else:
        store = Keystore(path=path, password=password)

    if store.alias_taken(entry.alias or ""):
        if not replace:
            raise KeytoolError(f"Alias <{entry.alias}> already exists in {path}")
        store.entries = [
            existing
            for existing in store.entries
            if existing.alias is None or existing.alias.casefold() != (entry.alias or "").casefold()
        ]

    if not entry.alias:
        raise KeytoolError("An entry must have a non-empty -alias")

    store.entries.append(entry)
    _write(store)


def delete_entry(path: str, alias: str, password: str) -> str:
    """Delete one entry, leaving the others intact. Returns the removed alias."""
    store = load_keystore(path, password)
    entry = store.find(alias)

    removed = entry.alias or alias
    store.entries = [e for e in store.entries if e is not entry]

    # An emptied store is still written: it is a valid PKCS#12 file with zero
    # entries, which is what keytool leaves behind.
    _write(store)
    return removed
