#!/usr/bin/env python3
"""Key pair, certificate and CSR generation.

P0 scope (see GAPS.md):

* `-keyalg` is actually honoured -- RSA, EC, DSA, Ed25519 and Ed448 -- and an
  unsupported value is rejected explicitly instead of silently producing RSA.
* `-sigalg` is actually honoured, and a signature algorithm that is not valid
  for the chosen key type is rejected with a helpful message.
* `-dname` is split on *unescaped* commas, so values such as
  ``CN=Doe\\, John`` survive instead of being silently truncated.
* Bad input raises `KeytoolError` rather than leaking a traceback.
"""

from __future__ import annotations

import datetime
import re
from typing import Any, Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID, ObjectIdentifier

from .errors import KeytoolError

# --------------------------------------------------------------------------- #
# Key algorithms
# --------------------------------------------------------------------------- #

RSA = "RSA"
EC = "EC"
DSA = "DSA"
ED25519 = "ED25519"
ED448 = "ED448"

SUPPORTED_KEY_ALGORITHMS = (RSA, EC, DSA, ED25519, ED448)

#: Name to show the user (keytool writes "Ed25519", not "ED25519").
DISPLAY_KEY_ALGORITHM: dict[str, str] = {
    RSA: "RSA",
    EC: "EC",
    DSA: "DSA",
    ED25519: "Ed25519",
    ED448: "Ed448",
}

#: Key sizes used when `-keysize` is not supplied. EdDSA has a fixed key size.
#: Key sizes used when `-keysize` is not supplied, matching keytool's
#: documented defaults (JDK 27): RSA 3072, EC 384, DSA 2048. EdDSA is fixed.
DEFAULT_KEY_SIZE: dict[str, Optional[int]] = {
    RSA: 3072,
    EC: 384,
    DSA: 2048,
    ED25519: None,
    ED448: None,
}

#: `-keysize` -> named curve for EC keys (matches keytool's usual names).
EC_CURVES: dict[int, type] = {
    256: ec.SECP256R1,
    384: ec.SECP384R1,
    521: ec.SECP521R1,
}

_MIN_RSA_BITS = 1024
_MAX_RSA_BITS = 16384
_MIN_DSA_BITS = 1024
_MAX_DSA_BITS = 3072


def normalize_key_algorithm(key_alg: str) -> str:
    """Validate and normalise a `-keyalg` value (keytool names are case-insensitive)."""
    alg = (key_alg or "").strip().upper()
    if alg not in SUPPORTED_KEY_ALGORITHMS:
        supported = ", ".join(DISPLAY_KEY_ALGORITHM[a] for a in SUPPORTED_KEY_ALGORITHMS)
        raise KeytoolError(
            f"Unsupported -keyalg value: {key_alg!r}. Supported values: {supported}"
        )
    return alg


def display_key_algorithm(key_alg: str) -> str:
    """User-facing name for a normalised key algorithm."""
    return DISPLAY_KEY_ALGORITHM.get(key_alg.strip().upper(), key_alg)


def validate_key_size(alg: str, key_size: Optional[int]) -> Optional[int]:
    """Check `-keysize` against the limits of the chosen algorithm."""
    if alg in (ED25519, ED448):
        if key_size is not None:
            raise KeytoolError(f"-keysize is not applicable to {alg} keys")
        return None

    size = DEFAULT_KEY_SIZE[alg] if key_size is None else key_size

    if alg == RSA:
        if not _MIN_RSA_BITS <= size <= _MAX_RSA_BITS:
            raise KeytoolError(
                f"Invalid -keysize {size} for RSA (must be between "
                f"{_MIN_RSA_BITS} and {_MAX_RSA_BITS})"
            )
    elif alg == DSA:
        if not _MIN_DSA_BITS <= size <= _MAX_DSA_BITS:
            raise KeytoolError(
                f"Invalid -keysize {size} for DSA (must be between "
                f"{_MIN_DSA_BITS} and {_MAX_DSA_BITS})"
            )
    elif alg == EC:
        if size not in EC_CURVES:
            raise KeytoolError(
                f"Invalid -keysize {size} for EC. Supported sizes: "
                f"{', '.join(str(s) for s in sorted(EC_CURVES))}"
            )
    return size


def generate_key_pair(key_alg: str, key_size: Optional[int] = None):
    """Generate a private key for `key_alg` (`-keyalg` / `-keysize`)."""
    alg = normalize_key_algorithm(key_alg)
    size = validate_key_size(alg, key_size)

    if alg == RSA:
        return rsa.generate_private_key(public_exponent=65537, key_size=size)
    if alg == EC:
        return ec.generate_private_key(EC_CURVES[size]())
    if alg == DSA:
        return dsa.generate_private_key(key_size=size)
    if alg == ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    return ed448.Ed448PrivateKey.generate()


def key_algorithm_of(key: Any) -> str:
    """Map a loaded private/public key object back to a keytool algorithm name."""
    if isinstance(key, rsa.RSAPrivateKey):
        return RSA
    if isinstance(key, rsa.RSAPublicKey):
        return RSA
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return EC
    if isinstance(key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return DSA
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return ED25519
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return ED448
    return type(key).__name__


def describe_public_key(key: Any) -> str:
    """Human-readable public key description, e.g. ``2048-bit RSA key``."""
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return f"{key.key_size}-bit RSA key"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return f"{key.curve.key_size}-bit EC key ({key.curve.name})"
    if isinstance(key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return f"{key.key_size}-bit DSA key"
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519 key"
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "Ed448 key"
    return type(key).__name__


# --------------------------------------------------------------------------- #
# Signature algorithms
# --------------------------------------------------------------------------- #

#: keytool-style signature algorithm name -> hash used to build it.
#: ``None`` means the algorithm carries its own hash (EdDSA).
_SIGNATURE_ALGORITHMS: dict[str, dict[str, Optional[Callable[[], Any]]]] = {
    RSA: {
        "SHA256WITHRSA": hashes.SHA256,
        "SHA384WITHRSA": hashes.SHA384,
        "SHA512WITHRSA": hashes.SHA512,
        "SHA1WITHRSA": hashes.SHA1,
    },
    EC: {
        "SHA256WITHECDSA": hashes.SHA256,
        "SHA384WITHECDSA": hashes.SHA384,
        "SHA512WITHECDSA": hashes.SHA512,
        "SHA1WITHECDSA": hashes.SHA1,
    },
    DSA: {
        "SHA256WITHDSA": hashes.SHA256,
        "SHA384WITHDSA": hashes.SHA384,
        "SHA512WITHDSA": hashes.SHA512,
        "SHA1WITHDSA": hashes.SHA1,
    },
    ED25519: {"ED25519": None},
    ED448: {"ED448": None},
}

DEFAULT_SIGNATURE_ALGORITHM: dict[str, str] = {
    RSA: "SHA256withRSA",
    EC: "SHA256withECDSA",
    DSA: "SHA256withDSA",
    ED25519: "Ed25519",
    ED448: "Ed448",
}


def default_signature_algorithm(private_key: Any) -> str:
    """Pick keytool's default `-sigalg` for a key, which depends on key size.

    From the keytool documentation::

        DSA   any size   SHA256withDSA
        RSA   < 624      SHA256withRSA
              <= 7680    SHA384withRSA
              > 7680     SHA512withRSA
        EC    < 512      SHA384withECDSA
              >= 512     SHA512withECDSA
        EdDSA 255/448    Ed25519/Ed448
    """
    key_alg = key_algorithm_of(private_key)

    if key_alg == RSA:
        if private_key.key_size < 624:
            return "SHA256withRSA"
        if private_key.key_size <= 7680:
            return "SHA384withRSA"
        return "SHA512withRSA"

    if key_alg == EC:
        return "SHA384withECDSA" if private_key.curve.key_size < 512 else "SHA512withECDSA"

    if key_alg == DSA:
        return "SHA256withDSA"

    return DEFAULT_SIGNATURE_ALGORITHM[key_alg]


def resolve_signature_algorithm(private_key: Any, sig_alg: Optional[str] = None) -> Optional[Any]:
    """Return the `hashes` instance for `-sigalg`, or ``None`` for EdDSA.

    When `-sigalg` is omitted the default follows keytool's size-dependent table
    rather than always using SHA-256.
    """
    key_alg = key_algorithm_of(private_key)
    available = _SIGNATURE_ALGORITHMS.get(key_alg, {})

    if sig_alg is None:
        sig_alg = default_signature_algorithm(private_key)

    name = sig_alg.strip().upper()
    if name not in available:
        raise KeytoolError(
            f"Unsupported -sigalg value {sig_alg!r} for a {key_alg} key. "
            f"Supported values: {', '.join(sorted(available))}"
        )

    factory = available[name]
    return None if factory is None else factory()


def signature_algorithm_name(certificate: x509.Certificate) -> str:
    """Render a certificate's signature algorithm the way keytool does."""
    public_key = certificate.public_key()
    key_alg = key_algorithm_of(public_key)
    if key_alg in (ED25519, ED448):
        return key_alg.capitalize() if key_alg == ED448 else "Ed25519"
    try:
        hash_name = certificate.signature_hash_algorithm.name
    except Exception:  # pragma: no cover - unusual/unsupported signature OID
        return certificate.signature_algorithm_oid.dotted_string
    label = {RSA: "RSA", EC: "ECDSA", DSA: "DSA"}.get(key_alg, key_alg)
    return f"{hash_name.upper()}with{label}"


# --------------------------------------------------------------------------- #
# Distinguished names
# --------------------------------------------------------------------------- #

#: keytool / RFC 2253 attribute keyword -> X.509 OID.
_ATTRIBUTE_OIDS: dict[str, Any] = {
    "CN": NameOID.COMMON_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "C": NameOID.COUNTRY_NAME,
    "STREET": NameOID.STREET_ADDRESS,
    "DC": NameOID.DOMAIN_COMPONENT,
    "UID": NameOID.USER_ID,
    "E": NameOID.EMAIL_ADDRESS,
    "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
    "SERIALNUMBER": NameOID.SERIAL_NUMBER,
    "SN": NameOID.SURNAME,
    "GIVENNAME": NameOID.GIVEN_NAME,
    "T": NameOID.TITLE,
}

DEFAULT_DNAME = "CN=Keytool Python Default, O=KeytoolReplica, C=ES"


def _split_rdns(dname: str) -> list[str]:
    """Split a DN on commas that are not backslash-escaped."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for char in dname:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)

    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _split_multi_valued(rdn: str) -> list[str]:
    """Split a multi-valued RDN (``CN=Foo+OU=Bar``) on unescaped ``+``."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for char in rdn:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == "+":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)

    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _unescape(value: str) -> str:
    """Resolve RFC 2253 escapes: ``\\,`` -> ``,`` and ``\\41`` -> ``A``."""
    result: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue

        index += 1
        if index >= len(value):
            result.append("\\")
            break

        following = value[index]
        # A pair of hex digits is a raw octet (RFC 2253 section 3).
        if (
            index + 1 < len(value)
            and re.fullmatch(r"[0-9a-fA-F]{2}", value[index : index + 2])
        ):
            result.append(chr(int(value[index : index + 2], 16)))
            index += 2
            continue

        result.append(following)
        index += 1

    return "".join(result)


def _normalise_oid(value: str) -> Optional[str]:
    """Return the OID for a numeric attribute name, e.g. ``2.5.4.3``."""
    return value if re.fullmatch(r"\d+(?:\.\d+)+", value) else None


def parse_dname(dname: Optional[str]) -> x509.Name:
    """Parse a `-dname` string into an `x509.Name` following RFC 2253.

    Supports escaped separators, hex escapes, multi-valued RDNs
    (``CN=Foo+OU=Bar``) and numeric OID attribute names. Unknown keywords and
    invalid values are errors rather than silently skipped attributes.
    """
    if not dname or not dname.strip():
        dname = DEFAULT_DNAME

    rdn_groups: list[list[x509.NameAttribute]] = []

    for rdn in _split_rdns(dname):
        group: list[x509.NameAttribute] = []
        for component in _split_multi_valued(rdn):
            if "=" not in component:
                raise KeytoolError(
                    f"Malformed -dname component {component!r}: expected the form "
                    f"TYPE=value (hint: escape separators, e.g. CN=Doe\\, John)"
                )

            raw_key, raw_value = component.split("=", 1)
            key = raw_key.strip().upper()
            value = _unescape(raw_value.strip())

            oid = _ATTRIBUTE_OIDS.get(key)
            if oid is None:
                numeric = _normalise_oid(raw_key.strip())
                if numeric is None:
                    raise KeytoolError(
                        f"Unknown -dname attribute {raw_key.strip()!r}. "
                        f"Known attributes: {', '.join(sorted(_ATTRIBUTE_OIDS))}"
                    )
                oid = ObjectIdentifier(numeric)

            if not value:
                raise KeytoolError(f"-dname attribute {raw_key.strip()} has an empty value")
            if key == "C" and len(value) != 2:
                raise KeytoolError(
                    f"Invalid country code {value!r}: a country (C) must be exactly 2 characters"
                )

            group.append(x509.NameAttribute(oid, value))

        if group:
            rdn_groups.append(group)

    if not rdn_groups:
        raise KeytoolError("The subject (-dname) must contain at least one attribute")

    # An X.500 name is written most-specific-first (RFC 2253) but encoded in the
    # opposite order (RFC 4514 section 2.1), which is what keytool does. Note
    # `cryptography` models one attribute per RDN, so a multi-valued RDN is
    # flattened into consecutive RDNs.
    attributes = [attribute for group in reversed(rdn_groups) for attribute in group]
    return x509.Name(attributes)


# --------------------------------------------------------------------------- #
# Start dates
# --------------------------------------------------------------------------- #

_RELATIVE_STARTDATE = re.compile(r"([+-])(\d+)([ymdHMS])")
_ABSOLUTE_STARTDATE = re.compile(
    r"(\d{4})/(\d{1,2})/(\d{1,2})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?"
)

_RELATIVE_UNITS = {
    "y": lambda n: datetime.timedelta(days=365 * n),
    "d": lambda n: datetime.timedelta(days=n),
    "H": lambda n: datetime.timedelta(hours=n),
    "m": lambda n: datetime.timedelta(minutes=n),
    "S": lambda n: datetime.timedelta(seconds=n),
}


def parse_startdate(value: str) -> datetime.datetime:
    """Parse `-startdate`, accepting keytool's two forms.

    * relative: ``-30d``, ``+1y``, ``+6H`` (units: y d H m S)
    * absolute: ``2027/01/02`` or ``2027/01/02 03:04:05`` (local time)
    """
    text = value.strip()
    if not text:
        raise KeytoolError("-startdate requires a value")

    relative = _RELATIVE_STARTDATE.fullmatch(text)
    if relative:
        sign, number, unit = relative.groups()
        delta = _RELATIVE_UNITS[unit](int(number))
        now = datetime.datetime.now(datetime.timezone.utc)
        return now - delta if sign == "-" else now + delta

    absolute = _ABSOLUTE_STARTDATE.fullmatch(text)
    if absolute:
        year, month, day, hour, minute, second = absolute.groups()
        try:
            naive = datetime.datetime(
                int(year),
                int(month),
                int(day),
                int(hour) if hour else 0,
                int(minute) if minute else 0,
                int(second) if second else 0,
            )
        except ValueError as error:
            raise KeytoolError(f"Invalid -startdate {value!r}: {error}") from error
        # keytool reads absolute start dates in the local time zone.
        return naive.astimezone()

    raise KeytoolError(
        f"Invalid -startdate {value!r}. Use yyyy/mm/dd[ HH:MM:SS] or a relative "
        f"form such as -30d or +1y"
    )


# --------------------------------------------------------------------------- #
# Certificates
# --------------------------------------------------------------------------- #


def _apply_extensions(
    builder: Any,
    extensions: Optional[list[tuple[x509.ExtensionType, bool]]],
    public_key: Any,
    add_subject_key_identifier: bool,
) -> Any:
    applied: set[str] = set()

    for value, critical in extensions or []:
        oid = value.oid.dotted_string
        if oid in applied:
            raise KeytoolError(f"Duplicate -ext for extension {oid}")
        applied.add(oid)
        builder = builder.add_extension(value, critical)

    # keytool always creates a SubjectKeyIdentifier, unless the caller supplied
    # one explicitly.
    ski_oid = x509.SubjectKeyIdentifier.oid.dotted_string
    if add_subject_key_identifier and ski_oid not in applied:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )

    return builder


def create_self_signed_certificate(
    private_key: Any,
    dname: str,
    validity_days: int = 365,
    sig_alg: Optional[str] = None,
    startdate: Optional[str] = None,
    extensions: Optional[list[tuple[x509.ExtensionType, bool]]] = None,
) -> x509.Certificate:
    """Build a self-signed certificate for `private_key` (`-genkeypair`)."""
    if validity_days <= 0:
        raise KeytoolError(f"Invalid -validity {validity_days}: must be a positive number of days")

    subject = parse_dname(dname)
    not_before = parse_startdate(startdate) if startdate else datetime.datetime.now(
        datetime.timezone.utc
    )
    hash_algorithm = resolve_signature_algorithm(private_key, sig_alg)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=validity_days))
    )
    builder = _apply_extensions(
        builder, extensions, private_key.public_key(), add_subject_key_identifier=True
    )

    if hash_algorithm is None:
        return builder.sign(private_key, None)
    return builder.sign(private_key, hash_algorithm)


def create_certificate_request(
    private_key: Any,
    subject: x509.Name,
    sig_alg: Optional[str] = None,
    extensions: Optional[list[tuple[x509.ExtensionType, bool]]] = None,
) -> x509.CertificateSigningRequest:
    """Build a PKCS#10 CSR (`-certreq`), honouring `-sigalg` and `-ext`."""
    hash_algorithm = resolve_signature_algorithm(private_key, sig_alg)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    for value, critical in extensions or []:
        builder = builder.add_extension(value, critical)

    if hash_algorithm is None:
        return builder.sign(private_key, None)
    return builder.sign(private_key, hash_algorithm)


# --------------------------------------------------------------------------- #
# Serialisation / inspection
# --------------------------------------------------------------------------- #


def serialize_certificate(certificate: x509.Certificate, rfc: bool = False) -> bytes:
    """PEM (`-rfc`) or DER encoding of a certificate."""
    encoding = serialization.Encoding.PEM if rfc else serialization.Encoding.DER
    return certificate.public_bytes(encoding)


def complete_chain(
    leaf: x509.Certificate, candidates: list[x509.Certificate]
) -> list[x509.Certificate]:
    """Order a certificate chain by matching each issuer to a subject.

    Mirrors what keytool does when importing a reply: the leaf is followed by
    whichever issuer certificate is available, and so on up to a self-signed
    root. Certificates that cannot be linked are ignored.
    """
    chain: list[x509.Certificate] = []
    remaining = [c for c in candidates if c.public_bytes(serialization.Encoding.DER) != leaf.public_bytes(serialization.Encoding.DER)]
    current = leaf

    while current.subject != current.issuer:
        match = next(
            (c for c in remaining if c.subject == current.issuer), None
        )
        if match is None:
            break
        remaining.remove(match)
        chain.append(match)
        current = match
        if len(chain) > 16:  # defensive
            break

    return chain


def load_certificates_file(path: str) -> list[x509.Certificate]:
    """Load one or more certificates from a file (`-importcert`).

    Accepts a single PEM or DER certificate, several concatenated PEM
    certificates, or a PKCS#7/CMS chain.
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise KeytoolError(f"Can't open certificate file {path}: {error.strerror}") from error

    if b"-----BEGIN PKCS7-----" in data or b"-----BEGIN CMS-----" in data:
        try:
            certificates = pkcs7.load_pem_pkcs7_certificates(data)
        except Exception as error:
            raise KeytoolError(f"Malformed PKCS#7 file {path}: {error}") from error
        if certificates:
            return list(certificates)

    # PEM: load every certificate block.
    pem_blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL
    )
    if pem_blocks:
        certificates = []
        for block in pem_blocks:
            try:
                certificates.append(x509.load_pem_x509_certificate(block))
            except ValueError as error:
                raise KeytoolError(f"Malformed certificate in {path}: {error}") from error
        return certificates

    # PKCS#7 in DER form.
    try:
        certificates = pkcs7.load_der_pkcs7_certificates(data)
        if certificates:
            return list(certificates)
    except Exception:
        pass

    # Last resort: a single DER certificate.
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError as error:
        raise KeytoolError(f"Not an X.509 certificate: {path}") from error


def load_certificate_file(path: str) -> x509.Certificate:
    """Load a single certificate from a PEM or DER file (`-printcert`)."""
    return load_certificates_file(path)[0]


def format_fingerprint(digest: bytes) -> str:
    """Format a digest the way keytool does: uppercase hex, colon separated."""
    return ":".join(f"{byte:02X}" for byte in digest)


def fingerprint(certificate: x509.Certificate, algorithm: Any) -> str:
    return format_fingerprint(certificate.fingerprint(algorithm))


def format_extension(extension: x509.Extension) -> str:
    """Render an extension value roughly the way keytool does."""
    value = extension.value

    if isinstance(value, x509.BasicConstraints):
        return "BasicConstraints:[\n  CA:{}\n]".format("TRUE" if value.ca else "FALSE")

    if isinstance(value, x509.KeyUsage):
        names = [
            ("digital_signature", "digitalSignature"),
            ("content_commitment", "nonRepudiation"),
            ("key_encipherment", "keyEncipherment"),
            ("data_encipherment", "dataEncipherment"),
            ("key_agreement", "keyAgreement"),
            ("key_cert_sign", "keyCertSign"),
            ("crl_sign", "cRLSign"),
            ("encipher_only", "encipherOnly"),
            ("decipher_only", "decipherOnly"),
        ]
        enabled = []
        for attr, label in names:
            try:
                if getattr(value, attr, False):
                    enabled.append(label)
            except ValueError:
                # encipher_only/decipher_only are undefined without keyAgreement.
                continue
        return "KeyUsage:[\n" + "".join(f"  {name}\n" for name in enabled) + "]"

    if isinstance(value, x509.ExtendedKeyUsage):
        usages = []
        for oid in value:
            usages.append(getattr(oid, "_name", None) or oid.dotted_string)
        return "ExtendedKeyUsage:[\n" + "".join(f"  {u}\n" for u in usages) + "]"

    if isinstance(value, x509.SubjectAlternativeName):
        return "SubjectAlternativeName:[\n" + "".join(
            f"  {type(name).__name__}: {name.value}\n" for name in value
        ) + "]"

    return repr(value)


def certificate_info(certificate: x509.Certificate) -> dict[str, Any]:
    """Collect the fields both `-list -v` and `-printcert` display."""
    return {
        "owner": format_dname(certificate.subject),
        "issuer": format_dname(certificate.issuer),
        "serial_number": format(certificate.serial_number, "X"),
        "not_valid_before": certificate.not_valid_before_utc,
        "not_valid_after": certificate.not_valid_after_utc,
        "version": certificate.version.name.lstrip("v"),
        "signature_algorithm": signature_algorithm_name(certificate),
        "public_key": describe_public_key(certificate.public_key()),
        "sha1": fingerprint(certificate, hashes.SHA1()),
        "sha256": fingerprint(certificate, hashes.SHA256()),
        "extensions": [
            (extension.oid.dotted_string, extension.critical, format_extension(extension))
            for extension in certificate.extensions
        ],
    }


def format_dname(name: x509.Name) -> str:
    """Render a DN the way keytool does.

    keytool prints the RFC 2253 form (most specific first), which is the reverse
    of the DER RDN order, separated by ``", "``.
    """
    return ", ".join(attribute.rfc4514_string() for attribute in reversed(list(name)))


def format_date(value: datetime.datetime) -> str:
    """Format a timestamp the way keytool prints entry dates."""
    return value.strftime("%b %d, %Y")
