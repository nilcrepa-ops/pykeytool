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
from typing import Any, Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

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
DEFAULT_KEY_SIZE: dict[str, Optional[int]] = {
    RSA: 2048,
    EC: 256,
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


def resolve_signature_algorithm(private_key: Any, sig_alg: Optional[str] = None) -> Optional[Any]:
    """Return the `hashes` instance for `-sigalg`, or ``None`` for EdDSA.

    Raises `KeytoolError` when the algorithm is unknown or incompatible with the
    key type -- rather than silently falling back to SHA256, which is what the
    original implementation did.
    """
    key_alg = key_algorithm_of(private_key)
    available = _SIGNATURE_ALGORITHMS.get(key_alg, {})

    if sig_alg is None:
        sig_alg = DEFAULT_SIGNATURE_ALGORITHM[key_alg]

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


def _split_dname(dname: str) -> list[str]:
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


def _unescape(value: str) -> str:
    """Resolve RFC 2253 backslash escapes (``Doe\\, John`` -> ``Doe, John``)."""
    result: list[str] = []
    iterator = iter(value)
    for char in iterator:
        if char != "\\":
            result.append(char)
            continue
        following = next(iterator, None)
        if following is None:
            result.append("\\")
        elif following in ',+"\\<>;=#':
            result.append(following)
        else:
            # Not a recognised escape (keytool also allows \XX hex pairs);
            # keep the character rather than dropping data.
            result.append(following)
    return "".join(result)


def parse_dname(dname: Optional[str]) -> x509.Name:
    """Parse a `-dname` string into an `x509.Name`.

    Unknown attribute keywords are an error rather than a warning-and-skip:
    silently dropping an attribute used to produce a different subject than the
    one the user asked for.
    """
    if not dname or not dname.strip():
        dname = DEFAULT_DNAME

    attributes: list[x509.NameAttribute] = []

    for part in _split_dname(dname):
        if "=" not in part:
            raise KeytoolError(
                f"Malformed -dname component {part!r}: expected the form TYPE=value "
                f"(hint: escape commas inside a value, e.g. CN=Doe\\, John)"
            )
        raw_key, raw_value = part.split("=", 1)
        key = raw_key.strip().upper()
        value = _unescape(raw_value.strip())

        if key not in _ATTRIBUTE_OIDS:
            raise KeytoolError(
                f"Unknown -dname attribute {raw_key.strip()!r}. "
                f"Known attributes: {', '.join(sorted(_ATTRIBUTE_OIDS))}"
            )
        if not value:
            raise KeytoolError(f"-dname attribute {key} has an empty value")
        if key == "C" and len(value) != 2:
            raise KeytoolError(
                f"Invalid country code {value!r}: a country (C) must be exactly 2 characters"
            )

        attributes.append(x509.NameAttribute(_ATTRIBUTE_OIDS[key], value))

    if not attributes:
        raise KeytoolError("The subject (-dname) must contain at least one attribute")

    return x509.Name(attributes)


# --------------------------------------------------------------------------- #
# Certificates
# --------------------------------------------------------------------------- #


def create_self_signed_certificate(
    private_key: Any,
    dname: str,
    validity_days: int = 365,
    sig_alg: Optional[str] = None,
) -> x509.Certificate:
    """Build a self-signed certificate for `private_key` (`-genkeypair`)."""
    if validity_days <= 0:
        raise KeytoolError(f"Invalid -validity {validity_days}: must be a positive number of days")

    subject = parse_dname(dname)
    now = datetime.datetime.now(datetime.timezone.utc)
    hash_algorithm = resolve_signature_algorithm(private_key, sig_alg)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    if hash_algorithm is None:
        return builder.sign(private_key, None)
    return builder.sign(private_key, hash_algorithm)


def create_certificate_request(
    private_key: Any,
    subject: x509.Name,
    sig_alg: Optional[str] = None,
) -> x509.CertificateSigningRequest:
    """Build a PKCS#10 CSR (`-certreq`), honouring `-sigalg`."""
    hash_algorithm = resolve_signature_algorithm(private_key, sig_alg)
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
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


def load_certificate_file(path: str) -> x509.Certificate:
    """Load a certificate from a PEM or DER file (`-printcert -file`)."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise KeytoolError(f"Can't open certificate file {path}: {error.strerror}") from error

    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            return loader(data)
        except ValueError:
            continue

    raise KeytoolError(f"Not an X.509 certificate: {path}")


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
        enabled = [label for attr, label in names if getattr(value, attr, False)]
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
        "owner": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
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


def format_date(value: datetime.datetime) -> str:
    """Format a timestamp the way keytool prints entry dates."""
    return value.strftime("%b %d, %Y")
