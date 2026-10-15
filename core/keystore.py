"""PKCS#12 keystore access.

P0 scope (see GAPS.md):

* **No more silent data loss.** The original `save_keystore_pkcs12()` opened the
  file with ``"wb"`` and wrote a single entry, so generating a second alias
  destroyed the first one. We now inspect the existing store first and refuse to
  touch it instead of overwriting data we cannot represent.
* **Aliases are honoured.** Entry names come from the PKCS#12 ``friendlyName``
  attribute, so `-list -alias`, `-exportcert -alias` and `-delete -alias` can
  verify the alias the user asked for and fail clearly when it is unknown.

Known limitation, verified against a real 2-entry store written by keytool:
`cryptography`'s PKCS#12 API exposes **one** private key per file. In a
multi-entry store the remaining entries show up as "additional certificates",
distinguishable by carrying their own ``friendlyName``. We surface that as an
explicit error rather than letting those entries be mangled (which is what made
the old `delete` implementation wipe the whole store).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

from .errors import KeytoolError

KEYSTORE_TYPE = "PKCS12"

#: keytool's own wording, kept so scripts that grep for it keep working.
WRONG_PASSWORD_MESSAGE = "Keystore was tampered with, or password was incorrect"

MULTI_ENTRY_MESSAGE = (
    "this version cannot add entries to an existing PKCS#12 file, because Python's "
    "'cryptography' library exposes only one private key per file"
)


@dataclass
class Entry:
    """A single keystore entry."""

    alias: Optional[str]
    private_key: Any
    certificate: Optional[x509.Certificate]
    chain: list[x509.Certificate] = field(default_factory=list)

    @property
    def entry_type(self) -> str:
        if self.private_key is not None:
            return "PrivateKeyEntry"
        return "trustedCertEntry"


@dataclass
class Keystore:
    """The contents of a PKCS#12 file, as far as we can represent them."""

    path: str
    password: str
    entries: list[Entry] = field(default_factory=list)
    #: Aliases of entries that exist in the file but cannot be loaded/rewritten.
    unsupported_aliases: list[str] = field(default_factory=list)

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

        # The alias may exist in the file but be unrepresentable, which is a
        # different problem from "no such alias" and deserves its own message.
        for unsupported in self.unsupported_aliases:
            if unsupported.casefold() == wanted:
                raise KeytoolError(
                    f"Alias <{alias}> exists in {self.path} but cannot be read: "
                    f"{MULTI_ENTRY_MESSAGE}"
                )

        available = ", ".join(e.alias or "<unnamed>" for e in self.entries)
        raise KeytoolError(
            f"Alias <{alias}> does not exist in {self.path} (available: {available})"
        )

    @property
    def has_unsupported_entries(self) -> bool:
        return bool(self.unsupported_aliases)


def _decode_alias(raw: Optional[bytes]) -> Optional[str]:
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace")


def load_keystore(path: str, password: str) -> Keystore:
    """Read a PKCS#12 keystore."""
    if not os.path.exists(path):
        raise KeytoolError(f"Keystore file does not exist: {path}")
    if os.path.getsize(path) == 0:
        raise KeytoolError(f"Keystore file exists but is empty: {path}")

    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise KeytoolError(f"Can't read keystore {path}: {error.strerror}") from error

    try:
        contents = pkcs12.load_pkcs12(data, password.encode("utf-8"))
    except ValueError as error:
        message = str(error)
        if "Invalid password" in message:
            raise KeytoolError(WRONG_PASSWORD_MESSAGE) from error
        raise KeytoolError(f"Not a valid PKCS#12 keystore ({path}): {message}") from error

    store = Keystore(path=path, password=password)

    primary_alias = _decode_alias(contents.cert.friendly_name) if contents.cert else None
    if contents.key is not None or contents.cert is not None:
        store.entries.append(
            Entry(
                alias=primary_alias,
                private_key=contents.key,
                certificate=contents.cert.certificate if contents.cert else None,
            )
        )

    # Anything left over is either a real certificate chain, or -- if it carries
    # its own friendlyName -- another entry we are unable to represent.
    for extra in contents.additional_certs or []:
        extra_alias = _decode_alias(extra.friendly_name)
        if extra_alias is not None and extra_alias != primary_alias:
            store.unsupported_aliases.append(extra_alias)
        elif store.entries:
            store.entries[0].chain.append(extra.certificate)
        else:
            store.entries.append(
                Entry(alias=extra_alias, private_key=None, certificate=extra.certificate)
            )

    return store


def ensure_writable(path: str, password: str, action: str) -> None:
    """Fail loudly rather than truncating a store we cannot merge into.

    Call this *before* doing expensive work, so the user is not told a key pair
    was generated and then told it could not be stored.
    """
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return

    try:
        existing = load_keystore(path, password)
    except KeytoolError as error:
        raise KeytoolError(
            f"Refusing to {action}: {path} already exists and could not be read "
            f"({error}). Delete it or choose another -keystore."
        ) from error

    if existing.entries or existing.has_unsupported_entries:
        count = len(existing.entries) + len(existing.unsupported_aliases)
        noun = "entry" if count == 1 else "entries"
        raise KeytoolError(
            f"Refusing to {action}: {path} already contains {count} {noun} and "
            f"{MULTI_ENTRY_MESSAGE}. Delete {path} first, or use a different -keystore file."
        )


def save_entry(path: str, entry: Entry, password: str, action: str = "write the keystore") -> None:
    """Write a single-entry keystore, never destroying an existing one."""
    ensure_writable(path, password, action)

    if entry.private_key is None:
        raise KeytoolError("Cannot store an entry without a private key yet")

    alias = (entry.alias or "").casefold()
    if not alias:
        raise KeytoolError("An entry must have a non-empty -alias")

    data = pkcs12.serialize_key_and_certificates(
        name=alias.encode("utf-8"),
        key=entry.private_key,
        cert=entry.certificate,
        cas=entry.chain or None,
        encryption_algorithm=BestAvailableEncryption(password.encode("utf-8")),
    )

    try:
        with open(path, "wb") as handle:
            handle.write(data)
    except OSError as error:
        raise KeytoolError(f"Can't write keystore {path}: {error.strerror}") from error


def delete_entry(path: str, alias: str, password: str) -> tuple[str, bool]:
    """Delete the entry named `alias`.

    Returns ``(removed_alias, store_is_now_empty)``. Because `cryptography`
    cannot serialise an empty PKCS#12 store, removing the only entry removes the
    file; the caller reports that to the user.
    """
    store = load_keystore(path, password)
    entry = store.find(alias)

    if store.has_unsupported_entries:
        raise KeytoolError(
            f"Refusing to delete <{alias}> from {path}: {MULTI_ENTRY_MESSAGE}. "
            f"Deleting would discard: {', '.join(store.unsupported_aliases)}"
        )

    # Only one entry is representable, and it is the one we were asked to drop,
    # so the store becomes empty. There is no way to write a valid empty
    # PKCS#12 file, hence the file is removed instead of being truncated to 0
    # bytes (which keytool cannot read at all).
    os.remove(path)
    return entry.alias or alias, True
