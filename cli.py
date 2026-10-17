#!/usr/bin/env python3
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

VERSION = "0.3.0"

#: Default validity in days, matching keytool's own default (JDK 27: 90).
DEFAULT_VALIDITY = 90


def _add_common_options(parser: argparse.ArgumentParser, store_required: bool = False) -> None:
    """Options shared by every command that touches a keystore.

    `-keystore` and `-cacerts` are alternatives; the choice is validated by the
    command implementation (`resolve_store_path`).
    """
    parser.add_argument(
        "-keystore",
        default=None,
        required=store_required,
        help="keystore file (default: required unless -cacerts is used)",
    )
    parser.add_argument(
        "-cacerts",
        action="store_true",
        help="use the JDK cacerts truststore instead of -keystore",
    )
    parser.add_argument("-storepass", default=None, help="keystore password")
    parser.add_argument(
        "-storetype",
        default="PKCS12",
        choices=["PKCS12", "pkcs12", "JKS", "jks"],
        help="keystore type (JKS is read-only)",
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
        "-startdate",
        default=None,
        help="certificate start date: yyyy/mm/dd[ HH:MM:SS] or relative (-30d, +1y)",
    )
    gen.add_argument(
        "-ext",
        action="append",
        default=None,
        metavar="NAME[:critical][=VALUE]",
        help=(
            "X.509 extension; may be repeated. Names: bc, ku, eku, san, ian, sia, "
            "aia, crl (or an OID with a #hexDER value)"
        ),
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
    listing.add_argument(
        "-rfc", action="store_true", help="print certificates in PEM (RFC 1421) format"
    )

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
    printcert.add_argument(
        "-rfc", action="store_true", help="print the certificate in PEM format"
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
        "-ext",
        action="append",
        default=None,
        metavar="NAME[:critical][=VALUE]",
        help="extensions to request in the CSR; may be repeated",
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

    # --------------------------------------------------------------- importcert
    importcert = subparsers.add_parser(
        "importcert", help="import a certificate or a certificate chain"
    )
    importcert.add_argument("-alias", required=True, help="alias to store it under")
    _add_common_options(importcert)
    importcert.add_argument("-keypass", default=None, help="key password")
    importcert.add_argument(
        "-file", required=True, help="certificate file (PEM, DER or PKCS#7 chain)"
    )
    importcert.add_argument(
        "-noprompt", action="store_true", help="do not prompt for confirmation"
    )
    importcert.add_argument(
        "-trustcacerts", action="store_true", help="trust certificates from cacerts"
    )
    importcert.add_argument(
        "-cacertspass",
        default=None,
        help="cacerts password used with -trustcacerts (default: changeit)",
    )

    # ----------------------------------------------------------- importkeystore
    importkeystore = subparsers.add_parser(
        "importkeystore", help="import entries from another keystore"
    )
    importkeystore.add_argument("-srckeystore", required=True, help="source keystore")
    importkeystore.add_argument("-destkeystore", required=True, help="destination keystore")
    importkeystore.add_argument("-srcstorepass", default=None, help="source store password")
    importkeystore.add_argument("-deststorepass", default=None, help="destination store password")
    importkeystore.add_argument("-srcalias", default=None, help="only import this alias")
    importkeystore.add_argument("-destalias", default=None, help="alias in the destination")
    importkeystore.add_argument(
        "-noprompt", action="store_true", help="do not prompt"
    )
    importkeystore.add_argument(
        "-v", action="store_true", dest="verbose", help="verbose output"
    )

    return parser
