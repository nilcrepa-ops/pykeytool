#!/usr/bin/env python3
"""pykeytool entry point.

P0 fixes baked in here (see GAPS.md):

* The commands actually call the crypto layer -- the previous `main` printed the
  parsed arguments and did nothing else.
* Failures are reported as ``keytool error: <message>`` on **stderr** with exit
  status 1, instead of leaking a Python traceback on stdout.
* Aliases are verified on every alias-taking command.
"""

from __future__ import annotations

import getpass
import os
import sys
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives import hashes, serialization

from cli import create_parser
from core.errors import KeytoolError

try:
    from core import crypto, keystore
except (ImportError, KeytoolError) as error:
    # `asn1crypto` is required for PKCS#12 support; report a missing dependency
    # as a normal keytool error rather than an import traceback.
    print(f"keytool error: {error}", file=sys.stderr)
    raise SystemExit(1)

#: Minimum password length keytool enforces when a *new* password is set.
MIN_PASSWORD_LENGTH = 6


# --------------------------------------------------------------------------- #
# Error handling
# --------------------------------------------------------------------------- #


def fail(message: str) -> int:
    """Report a user-facing error the way keytool does."""
    print(f"keytool error: {message}", file=sys.stderr)
    return 1


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #


def _prompt_password(prompt: str, creating: bool) -> str:
    """Ask for a password interactively, retrying like keytool does."""
    for _ in range(3):
        try:
            password = getpass.getpass(prompt)
        except (EOFError, KeyboardInterrupt):
            raise KeytoolError("Password entry cancelled") from None

        if creating and len(password) < MIN_PASSWORD_LENGTH:
            print(
                f"keytool error: Password must be at least {MIN_PASSWORD_LENGTH} characters",
                file=sys.stderr,
            )
            continue
        return password

    raise KeytoolError("Too many failed password attempts")


def resolve_store_password(provided: Optional[str], creating: bool = False) -> str:
    """Return the store password, prompting when `-storepass` was omitted.

    The minimum length is only enforced when a password is being *set*, so that
    existing stores protected with a short password can still be opened (the old
    implementation rejected them on every command, including read-only ones).
    """
    if provided is not None:
        if creating and len(provided) < MIN_PASSWORD_LENGTH:
            raise KeytoolError(
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
            )
        return provided

    return _prompt_password("Enter keystore password: ", creating=creating)


def check_key_password(args: Any, store_password: str) -> str:
    """Handle `-keypass`.

    Separate key and store passwords are not supported yet -- `cryptography`
    takes a single password when writing a PKCS#12 file. Rather than silently
    ignoring the option (the old behaviour), we reject a differing value.
    """
    keypass = getattr(args, "keypass", None)
    if keypass is None:
        return store_password
    if keypass != store_password:
        raise KeytoolError(
            "-keypass must match -storepass: separate key and store passwords are "
            "not supported yet"
        )
    return keypass


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #


def _entry_date(entry: keystore.Entry) -> str:
    """Best available creation date.

    A PKCS#12 ``localKeyId``/time attribute is not exposed by `cryptography`, so
    a self-signed entry's `not_valid_before` -- which is the creation instant --
    is used instead.
    """
    if entry.certificate is None:
        return "unknown"
    return crypto.format_date(entry.certificate.not_valid_before_utc)


def _entry_fingerprint(entry: keystore.Entry) -> Optional[str]:
    if entry.certificate is None:
        return None
    return crypto.fingerprint(entry.certificate, hashes.SHA256())


def print_certificate_details(certificate: Any) -> None:
    info = crypto.certificate_info(certificate)
    print(f"Owner: {info['owner']}")
    print(f"Issuer: {info['issuer']}")
    print(f"Serial number: {info['serial_number']}")
    print(f"Valid from: {info['not_valid_before']} until: {info['not_valid_after']}")
    print("Certificate fingerprints:")
    print(f"\t SHA1: {info['sha1']}")
    print(f"\t SHA256: {info['sha256']}")


def print_verbose_certificate(certificate: Any) -> None:
    info = crypto.certificate_info(certificate)
    print(f"Signature algorithm name: {info['signature_algorithm']}")
    print(f"Subject Public Key Algorithm: {info['public_key']}")
    print(f"Version: {info['version']}")

    extensions = info["extensions"]
    if extensions:
        print("\nExtensions: ")
        for index, (oid, critical, value) in enumerate(extensions, start=1):
            print(f"\n#{index}: ObjectId: {oid} Criticality={'true' if critical else 'false'}")
            print(value)


def print_verbose_entry(entry: keystore.Entry) -> None:
    print(f"Alias name: {entry.alias or '<unnamed>'}")
    print(f"Creation date: {_entry_date(entry)}")
    print(f"Entry type: {entry.entry_type}")

    if entry.certificate is None:
        return

    print(f"Certificate chain length: {1 + len(entry.chain)}")
    print("Certificate[1]:")
    print_certificate_details(entry.certificate)
    print_verbose_certificate(entry.certificate)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_genkeypair(args: Any) -> int:
    password = resolve_store_password(args.storepass, creating=True)
    check_key_password(args, password)

    algorithm = crypto.normalize_key_algorithm(args.keyalg)
    key_size = crypto.validate_key_size(algorithm, args.keysize)
    effective_size = crypto.DEFAULT_KEY_SIZE[algorithm] if key_size is None else key_size

    # Refuse a taken alias before generating anything, so a failure never looks
    # like it half-succeeded (keytool does the same).
    keystore.ensure_alias_available(args.keystore, args.alias, password)

    private_key = crypto.generate_key_pair(algorithm, key_size)
    display_alg = crypto.display_key_algorithm(algorithm)

    if key_size is None:
        description = f"{display_alg} key pair"
    else:
        description = f"{effective_size:,} bit {display_alg} key pair"

    # keytool announces the work before doing it; the hash name is only known
    # once the key exists, so build the certificate first and print after.
    certificate = crypto.create_self_signed_certificate(
        private_key, args.dname, args.validity, args.sigalg
    )

    print(
        f"Generating {description} and self-signed certificate "
        f"({crypto.signature_algorithm_name(certificate)}) "
        f"with a validity of {args.validity} days"
    )
    print(f"\tfor: {certificate.subject.rfc4514_string()}")

    entry = keystore.Entry(
        alias=args.alias,
        private_key=private_key,
        certificate=certificate,
    )
    keystore.add_entry(args.keystore, entry, password)

    if args.verbose:
        print()
        print_verbose_entry(entry)
    return 0


def cmd_list(args: Any) -> int:
    password = resolve_store_password(args.storepass)
    store = keystore.load_keystore(args.keystore, password)

    # Resolve the alias before printing anything, so an unknown alias produces
    # only the error message.
    if args.alias is not None:
        entries = [store.find(args.alias)]
    else:
        entries = store.entries

    print(f"Keystore type: {keystore.KEYSTORE_TYPE}")

    total = len(entries)
    if total == 0:
        print("\nYour keystore contains 0 entries")
        return 0

    noun = "entry" if total == 1 else "entries"
    print(f"\nYour keystore contains {total} {noun}\n")

    for entry in entries:
        if args.verbose:
            print_verbose_entry(entry)
            print()
        else:
            digest = _entry_fingerprint(entry)
            print(f"{entry.alias or '<unnamed>'}, {_entry_date(entry)}, {entry.entry_type}, ")
            if digest:
                print(f"Certificate fingerprint (SHA-256): {digest}")

    return 0


def cmd_exportcert(args: Any) -> int:
    password = resolve_store_password(args.storepass)
    check_key_password(args, password)

    store = keystore.load_keystore(args.keystore, password)
    entry = store.find(args.alias)

    if entry.certificate is None:
        raise KeytoolError(f"Certificate not found for alias <{args.alias}>")

    data = crypto.serialize_certificate(entry.certificate, rfc=args.rfc)

    if args.file is None:
        # keytool writes to standard output when -file is omitted.
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return 0

    try:
        with open(args.file, "wb") as handle:
            handle.write(data)
    except OSError as error:
        raise KeytoolError(f"Can't write {args.file}: {error.strerror}") from error

    if args.verbose:
        print(f"Certificate stored in file <{args.file}>")
    return 0


def cmd_printcert(args: Any) -> int:
    certificate = crypto.load_certificate_file(args.file)
    print_certificate_details(certificate)
    if args.verbose:
        print_verbose_certificate(certificate)
    return 0


def cmd_certreq(args: Any) -> int:
    password = resolve_store_password(args.storepass)
    check_key_password(args, password)

    store = keystore.load_keystore(args.keystore, password)
    entry = store.find(args.alias)

    if entry.private_key is None:
        raise KeytoolError(f"Entry <{args.alias}> has no private key to sign a request with")

    subject = entry.certificate.subject if entry.certificate else crypto.parse_dname(None)
    request = crypto.create_certificate_request(entry.private_key, subject, args.sigalg)
    data = request.public_bytes(serialization.Encoding.PEM)

    if args.file is None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return 0

    try:
        with open(args.file, "wb") as handle:
            handle.write(data)
    except OSError as error:
        raise KeytoolError(f"Can't write {args.file}: {error.strerror}") from error

    print(f"Certification request stored in file <{args.file}>")
    return 0


def cmd_delete(args: Any) -> int:
    password = resolve_store_password(args.storepass)
    removed = keystore.delete_entry(args.keystore, args.alias, password)

    if args.verbose:
        print(f"Deleted entry <{removed}> from {args.keystore}")
    return 0


COMMANDS: dict[str, Callable[[Any], int]] = {
    "genkeypair": cmd_genkeypair,
    "list": cmd_list,
    "exportcert": cmd_exportcert,
    "printcert": cmd_printcert,
    "certreq": cmd_certreq,
    "delete": cmd_delete,
}


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main(argv: Optional[list[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    handler = COMMANDS.get(args.command)
    if handler is None:  # pragma: no cover - argparse rejects unknown commands
        return fail(f"Unknown command: {args.command}")

    try:
        return handler(args)
    except KeytoolError as error:
        return fail(str(error))
    except KeyboardInterrupt:  # pragma: no cover
        print("keytool error: cancelled", file=sys.stderr)
        return 1
    except Exception as error:  # unexpected: never show a bare traceback
        if os.environ.get("PYKEYTOOL_DEBUG"):
            raise
        return fail(f"unexpected {type(error).__name__}: {error}")


if __name__ == "__main__":
    sys.exit(main())
