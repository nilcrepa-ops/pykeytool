"""Command line interface definition.

The option surface is modelled on the real `keytool`: single-dash long options
(``-alias``, ``-keystore``, ...), one sub-command per keytool command, and
``-h`` / ``--help`` / ``-help`` accepted everywhere.

P0 fixes baked in here:

* ``-keysize`` and ``-validity`` are declared as ``int``. Previously any
  explicitly supplied value arrived as a string and crashed deep inside
  `cryptography` with a `TypeError`.
* ``-sigalg`` and ``-keyalg`` are real options rather than decoration.
"""

from __future__ import annotations

import argparse

from core.crypto import DEFAULT_DNAME, DEFAULT_KEY_SIZE, RSA

VERSION = "0.2.0"

#: Default validity in days, matching keytool's own default.
DEFAULT_VALIDITY = 365


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    """Options shared by every command that touches a keystore."""
    parser.add_argument("-keystore", required=True, help="keystore file")
    parser.add_argument("-storepass", default=None, help="keystore password")
    parser.add_argument(
        "-storetype",
        default="PKCS12",
        choices=["PKCS12", "pkcs12"],
        help="keystore type (only PKCS12 is supported so far)",
    )
    parser.add_argument(
        "-v", action="store_true", dest="verbose", help="verbose output"
    )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pykeytool",
        description="Keytool in Python for keys and certificates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog=(
            "Only a subset of keytool's commands is implemented so far; "
            "see GAPS.md for what is still missing."
        ),
    )
    parser.add_argument(
        "-h", "--help", "-help", action="help", help="show this help message and exit"
    )
    parser.add_argument(
        "-version", "--version", action="version", version=f"pykeytool {VERSION}"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # ---------------------------------------------------------------- genkeypair
    gen = subparsers.add_parser(
        "genkeypair", help="generate a key pair and a self-signed certificate"
    )
    gen.add_argument("-alias", required=True, help="alias for the new entry")
    _add_common_options(gen)
    gen.add_argument("-keypass", default=None, help="key password")
    gen.add_argument(
        "-dname",
        default=None,
        help=f'distinguished name, e.g. "CN=Alice, O=Example, C=ES" (default: {DEFAULT_DNAME})',
    )
    gen.add_argument(
        "-keyalg",
        default=RSA,
        help="key algorithm: RSA, EC, DSA, Ed25519 or Ed448 (default: %(default)s)",
    )
    gen.add_argument(
        "-keysize",
        type=int,
        default=None,
        help=(
            "key size in bits "
            f"(defaults: RSA {DEFAULT_KEY_SIZE['RSA']}, EC {DEFAULT_KEY_SIZE['EC']}, "
            f"DSA {DEFAULT_KEY_SIZE['DSA']})"
        ),
    )
    gen.add_argument(
        "-sigalg", default=None, help="signature algorithm, e.g. SHA384withRSA"
    )
    gen.add_argument(
        "-validity",
        type=int,
        default=DEFAULT_VALIDITY,
        help="validity period in days (default: %(default)s)",
    )

    # --------------------------------------------------------------------- list
    listing = subparsers.add_parser("list", help="list the entries in a keystore")
    _add_common_options(listing)
    listing.add_argument("-alias", default=None, help="only show this alias")

    # --------------------------------------------------------------- exportcert
    export = subparsers.add_parser("exportcert", help="export a certificate")
    export.add_argument("-alias", required=True, help="alias of the entry to export")
    _add_common_options(export)
    export.add_argument("-keypass", default=None, help="key password")
    export.add_argument(
        "-file",
        default=None,
        help="output file (default: write PEM to standard output)",
    )
    export.add_argument(
        "-rfc", action="store_true", help="PEM (RFC 1421) output instead of DER"
    )

    # ---------------------------------------------------------------- printcert
    printcert = subparsers.add_parser(
        "printcert", help="print the contents of a certificate file"
    )
    printcert.add_argument("-file", required=True, help="certificate file (PEM or DER)")
    printcert.add_argument(
        "-v", action="store_true", dest="verbose", help="verbose output"
    )

    # ------------------------------------------------------------------ certreq
    certreq = subparsers.add_parser(
        "certreq", help="generate a certificate signing request (CSR)"
    )
    certreq.add_argument("-alias", required=True, help="alias of the entry to use")
    _add_common_options(certreq)
    certreq.add_argument("-keypass", default=None, help="key password")
    certreq.add_argument(
        "-sigalg", default=None, help="signature algorithm, e.g. SHA384withRSA"
    )
    certreq.add_argument(
        "-file",
        default=None,
        help="output file (default: write PEM to standard output)",
    )

    # ------------------------------------------------------------------- delete
    delete = subparsers.add_parser("delete", help="delete a keystore entry")
    delete.add_argument("-alias", required=True, help="alias of the entry to delete")
    _add_common_options(delete)

    return parser
