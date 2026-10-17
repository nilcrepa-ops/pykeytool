"""X.509 extension handling for the `-ext` option.

The grammar matches Java keytool (JDK 27)::

    -ext {name{:critical}{=value}}

* ``name`` is one of the supported names below (case-insensitive) or an
  arbitrary OID.
* ``:critical`` (or ``:c``) marks the extension critical.
* For an OID name the value is the DER encoding of the extension value as hex,
  with any non-hex characters ignored.
* When the value is omitted the extension's default value is used.

Supported names, as accepted by keytool: ``bc``, ``ku``, ``eku``, ``san``,
``ian``, ``sia``, ``aia``, ``crl``, ``crldp``. ``ski`` is not a name because
keytool always creates a SubjectKeyIdentifier, which this module also does.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier

from .errors import KeytoolError

# --------------------------------------------------------------------------- #
# OIDs
# --------------------------------------------------------------------------- #

#: Access methods allowed inside AIA / SIA (case-insensitive), keytool's names.
AIA_METHODS: dict[str, str] = {
    "ocsp": "1.3.6.1.5.5.7.48.1",
    "caIssuers": "1.3.6.1.5.5.7.48.2",
}

SIA_METHODS: dict[str, str] = {
    "timeStamping": "1.3.6.1.5.5.7.48.3",
    "caRepository": "1.3.6.1.5.5.7.48.5",
}

#: keytool accepts names case-sensitively in camel case, plus unambiguous
#: prefixes and camel-case initials (``dig``, ``dS``, ``cRLS``).
EKU_NAMES: dict[str, str] = {
    "anyExtendedKeyUsage": "2.5.29.37.0",
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING.dotted_string,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING.dotted_string,
    "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string,
}

#: Key usage flag name -> `x509.KeyUsage` keyword.
KEY_USAGE_NAMES: dict[str, str] = {
    "digitalSignature": "digital_signature",
    "nonRepudiation": "content_commitment",
    "contentCommitment": "content_commitment",
    "keyEncipherment": "key_encipherment",
    "dataEncipherment": "data_encipherment",
    "keyAgreement": "key_agreement",
    "keyCertSign": "key_cert_sign",
    "cRLSign": "crl_sign",
    "encipherOnly": "encipher_only",
    "decipherOnly": "decipher_only",
}

#: Access method name -> OID (case-insensitive).
ACCESS_METHOD_NAMES: dict[str, str] = {
    "timeStamping": "1.3.6.1.5.5.7.48.3",
    "caRepository": "1.3.6.1.5.5.7.48.5",
}

GENERAL_NAME_TYPES = ("email", "uri", "dns", "ip", "oid")

_FALSE_VALUES = {"false", "no", "off", "0"}
_TRUE_VALUES = {"true", "yes", "on", "1"}


# --------------------------------------------------------------------------- #
# Spec parsing
# --------------------------------------------------------------------------- #


@dataclass
class ExtensionSpec:
    """One parsed `-ext` option."""

    name: str
    critical: bool
    value: Optional[str]

    @property
    def is_oid(self) -> bool:
        return bool(re.fullmatch(r"\d+(?:\.\d+)+", self.name))


def parse_spec(spec: str) -> ExtensionSpec:
    """Split ``name[:critical][=value]`` into its parts."""
    if not spec or not spec.strip():
        raise KeytoolError("-ext requires a value")

    text = spec.strip()
    name_part, _, value = text.partition("=")

    critical = False
    name = name_part
    if ":" in name_part:
        name, _, modifier = name_part.rpartition(":")
        if modifier.lower() in ("critical", "c"):
            critical = True
        else:
            raise KeytoolError(
                f"Unknown -ext modifier {modifier!r} in {spec!r} "
                f"(expected ':critical' or ':c')"
            )

    name = name.strip()
    if not name:
        raise KeytoolError(f"Missing extension name in {spec!r}")

    return ExtensionSpec(name=name, critical=critical, value=value if "=" in text else None)


# --------------------------------------------------------------------------- #
# Name helpers
# --------------------------------------------------------------------------- #


def _normalise(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _camel_initials(text: str) -> str:
    """``digitalSignature`` -> ``dS``, ``cRLSign`` -> ``cRLS``."""
    parts = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", text)
    return "".join(part[0] for part in parts if part)


def _resolve_usage(raw: str, table: dict[str, str], label: str) -> str:
    """Match a usage name, allowing keytool's abbreviations.

    keytool accepts the full camel-case name, an unambiguous prefix (``dig``),
    or the camel-case initials (``dS``, ``cRLS``). Its value names are
    case-sensitive.
    """
    candidate = raw.strip()
    if not candidate:
        raise KeytoolError(f"Empty {label} value")

    normalised = _normalise(candidate)

    for name, value in table.items():
        if _normalise(name) == normalised:
            return value

    prefix_matches = [name for name in table if _normalise(name).startswith(normalised)]
    if len({table[name] for name in prefix_matches}) == 1 and prefix_matches:
        return table[prefix_matches[0]]

    initial_matches = [name for name in table if _camel_initials(name) == candidate]
    if len({table[name] for name in initial_matches}) == 1 and initial_matches:
        return table[initial_matches[0]]

    raise KeytoolError(
        f"Unknown {label} value {candidate!r}. Known values: {', '.join(table)}"
    )


def _split_list(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


# --------------------------------------------------------------------------- #
# General names (SAN / IAN / AIA locations)
# --------------------------------------------------------------------------- #


def _general_name(kind: str, val: str) -> x509.GeneralName:
    kind_lower = kind.strip().lower()
    val = val.strip()

    if kind_lower == "dns":
        return x509.DNSName(val)
    if kind_lower == "ip":
        try:
            return x509.IPAddress(ipaddress.ip_address(val))
        except ValueError as error:
            raise KeytoolError(f"Invalid IP address in -ext: {val!r}") from error
    if kind_lower == "email":
        return x509.RFC822Name(val)
    if kind_lower == "uri":
        return x509.UniformResourceIdentifier(val)
    if kind_lower == "oid":
        try:
            return x509.RegisteredID(ObjectIdentifier(val))
        except ValueError as error:
            raise KeytoolError(f"Invalid OID in -ext: {val!r}") from error

    raise KeytoolError(
        f"Unknown general name type {kind!r} in -ext. "
        f"Known types: {', '.join(t.upper() for t in GENERAL_NAME_TYPES)}"
    )


def _parse_general_names(value: Optional[str], label: str) -> list[x509.GeneralName]:
    items = _split_list(value)
    if not items:
        raise KeytoolError(f"-ext {label} requires at least one type:value pair")

    names: list[x509.GeneralName] = []
    for item in items:
        kind, sep, rest = item.partition(":")
        if not sep:
            raise KeytoolError(
                f"Invalid -ext {label} item {item!r}: expected type:value "
                f"(types: {', '.join(t.upper() for t in GENERAL_NAME_TYPES)})"
            )
        # `email:foo@bar` splits on the first colon only, so re-join the rest.
        names.append(_general_name(kind, rest))
    return names


# --------------------------------------------------------------------------- #
# Individual extensions
# --------------------------------------------------------------------------- #


def _basic_constraints(value: Optional[str]) -> x509.BasicConstraints:
    ca = True
    path_length: Optional[int] = None

    if value is not None:
        for item in _split_list(value):
            key, sep, rest = item.partition(":")
            if not sep:
                # Bare number: short for ca:true,pathlen:<n>
                if item.isdigit():
                    ca, path_length = True, int(item)
                    continue
                raise KeytoolError(
                    f"Invalid -ext bc item {item!r}: expected ca:true|ca:false[,pathlen:N]"
                )

            key = key.strip().lower()
            rest = rest.strip()
            if key == "ca":
                lowered = rest.lower()
                if lowered in _TRUE_VALUES:
                    ca = True
                elif lowered in _FALSE_VALUES:
                    ca = False
                else:
                    raise KeytoolError(f"Invalid -ext bc ca value {rest!r}")
            elif key == "pathlen":
                if not rest.isdigit():
                    raise KeytoolError(f"Invalid -ext bc pathlen value {rest!r}")
                path_length = int(rest)
            else:
                raise KeytoolError(
                    f"Invalid -ext bc item {item!r}: expected ca:or pathlen:"
                )

    if not ca and path_length is not None:
        raise KeytoolError("-ext bc: pathlen is only valid with ca:true")

    return x509.BasicConstraints(ca=ca, path_length=path_length)


def _key_usage(value: Optional[str]) -> x509.KeyUsage:
    items = _split_list(value)
    if not items:
        raise KeytoolError("-ext ku requires at least one usage")

    flags = {name: False for name in KEY_USAGE_NAMES.values()}
    for item in items:
        flag = _resolve_usage(item, KEY_USAGE_NAMES, "key usage")
        flags[flag] = True

    if not flags["key_agreement"]:
        # cryptography refuses encipher_only/decipher_only unless keyAgreement
        # is set; keytool rejects the combination as well.
        if flags["encipher_only"] or flags["decipher_only"]:
            raise KeytoolError(
                "-ext ku: encipherOnly/decipherOnly require keyAgreement"
            )

    return x509.KeyUsage(**flags)


def _extended_key_usage(value: Optional[str]) -> x509.ExtendedKeyUsage:
    items = _split_list(value)
    if not items:
        raise KeytoolError("-ext eku requires at least one usage")

    oids: list[ObjectIdentifier] = []
    for item in items:
        if re.fullmatch(r"\d+(?:\.\d+)+", item):
            oids.append(ObjectIdentifier(item))
            continue
        oid = _resolve_usage(item, EKU_NAMES, "extended key usage")
        oids.append(ObjectIdentifier(oid))
    return x509.ExtendedKeyUsage(oids)


def _access_descriptions(
    value: Optional[str], label: str, allowed: dict[str, str]
) -> list[x509.AccessDescription]:
    items = _split_list(value)
    if not items:
        raise KeytoolError(f"-ext {label} requires at least one entry")

    descriptions: list[x509.AccessDescription] = []
    for item in items:
        method, sep, rest = item.partition(":")
        if not sep:
            raise KeytoolError(
                f"Invalid -ext {label} item {item!r}: expected method:type:value"
            )

        method_key = method.strip().lower()
        known = {name.lower(): oid for name, oid in allowed.items()}
        if method_key in known:
            method_oid = known[method_key]
        elif re.fullmatch(r"\d+(?:\.\d+)+", method.strip()):
            method_oid = method.strip()
        else:
            raise KeytoolError(
                f"Unknown {label} method {method!r}. Known methods: {', '.join(allowed)}"
            )

        kind, sep, location = rest.partition(":")
        if not sep:
            raise KeytoolError(
                f"Invalid -ext {label} item {item!r}: expected method:type:value"
            )
        descriptions.append(
            x509.AccessDescription(
                ObjectIdentifier(method_oid), _general_name(kind, location)
            )
        )
    return descriptions


def _crl_distribution_points(value: Optional[str]) -> x509.CRLDistributionPoints:
    items = _split_list(value)
    if not items:
        raise KeytoolError("-ext crl requires at least one uri:value")

    points: list[x509.DistributionPoint] = []
    for item in items:
        kind, sep, location = item.partition(":")
        if not sep:
            raise KeytoolError(
                f"Invalid -ext crl item {item!r}: expected uri:http://..."
            )
        points.append(
            x509.DistributionPoint(
                full_name=[_general_name(kind, location)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        )
    return x509.CRLDistributionPoints(points)


def _hex_value(value: Optional[str]) -> bytes:
    """Interpret an OID extension value: hex DER, non-hex characters ignored."""
    if value is None:
        return b""
    digits = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(digits) % 2:
        raise KeytoolError(
            f"Odd number of hex digits in -ext value {value!r} (expected DER hex)"
        )
    return bytes.fromhex(digits)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


@dataclass
class Extension:
    """An extension ready to be added to a certificate or CSR."""

    value: x509.ExtensionType
    critical: bool


_HELPERS = {
    "bc": ("basicconstraints", _basic_constraints),
    "basicconstraints": ("basicconstraints", _basic_constraints),
    "ku": ("keyusage", _key_usage),
    "keyusage": ("keyusage", _key_usage),
    "eku": ("extendedkeyusage", _extended_key_usage),
    "extendedkeyusage": ("extendedkeyusage", _extended_key_usage),
}

_SAN_ALIASES = {
    "san": "subjectalternativename",
    "subjectalternativename": "subjectalternativename",
    "ian": "issueralternativename",
    "issueralternativename": "issueralternativename",
}

_ACCESS_ALIASES = {
    "aia": "authorityinfoaccess",
    "authorityinfoaccess": "authorityinfoaccess",
    "sia": "subjectinfoaccess",
    "subjectinfoaccess": "subjectinfoaccess",
}

_CRL_ALIASES = {"crl", "crldp", "crldistributionpoints", "crldistributionpoint"}


def build_extension(spec: ExtensionSpec) -> Extension:
    """Turn one parsed `-ext` spec into a cryptography extension object."""
    name = _normalise(spec.name)

    if spec.is_oid:
        return Extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier(spec.name), _hex_value(spec.value)
            ),
            spec.critical,
        )

    if name in _HELPERS:
        _, builder = _HELPERS[name]
        return Extension(builder(spec.value), spec.critical)

    if name in _SAN_ALIASES:
        target = _SAN_ALIASES[name]
        names = _parse_general_names(spec.value, name)
        value: x509.ExtensionType = (
            x509.SubjectAlternativeName(names)
            if target == "subjectalternativename"
            else x509.IssuerAlternativeName(names)
        )
        return Extension(value, spec.critical)

    if name in _ACCESS_ALIASES:
        target = _ACCESS_ALIASES[name]
        allowed = AIA_METHODS if target == "authorityinfoaccess" else SIA_METHODS
        descriptions = _access_descriptions(spec.value, name, allowed)
        if target == "authorityinfoaccess":
            return Extension(
                x509.AuthorityInformationAccess(descriptions), spec.critical
            )
        return Extension(x509.SubjectInformationAccess(descriptions), spec.critical)

    if name in _CRL_ALIASES:
        return Extension(_crl_distribution_points(spec.value), spec.critical)

    if name == "honored":
        raise KeytoolError(
            "-ext honored is only meaningful for -gencert, which is not implemented yet"
        )

    raise KeytoolError(
        f"Unsupported -ext name {spec.name!r}. Supported names: {', '.join(SUPPORTED_NAMES)}, "
        f"or an OID such as 2.5.29.14=#hexDER"
    )


SUPPORTED_NAMES = ("bc", "ku", "eku", "san", "ian", "sia", "aia", "crl", "crldp")


def parse_extensions(specs: Optional[list[str]]) -> list[Extension]:
    """Parse every `-ext` option, rejecting duplicate extension types."""
    if not specs:
        return []

    extensions: list[Extension] = []
    seen: set[str] = set()

    for spec in specs:
        parsed = parse_spec(spec)
        extension = build_extension(parsed)

        # keytool keeps the last occurrence of a duplicated extension.
        key = extension.value.oid.dotted_string
        if key in seen:
            extensions = [e for e in extensions if e.value.oid.dotted_string != key]
        seen.add(key)
        extensions.append(extension)

    return extensions


def keytool_args(specs: Optional[list[str]]) -> list[tuple[x509.ExtensionType, bool]]:
    """Convenience wrapper for the certificate builder."""
    return [(e.value, e.critical) for e in parse_extensions(specs)]
