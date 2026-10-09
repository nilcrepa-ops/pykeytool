import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key(bit_size: int = 2048):
    """Generate an RSA private key"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bit_size,
    )
    return private_key

def parse_dname(dname_str: str) -> x509.Name:
    if not dname_str:
        return x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Keytool Python Default'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'ES'),
            
        ])
    
    attributes = []

    oid_mapping = {
        'CN': NameOID.COMMON_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'L': NameOID.LOCALITY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'C': NameOID.COUNTRY_NAME,
    }

    parts = dname_str.split(',')
    for part in parts:
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            key = key.strip().upper()
            value = value.strip()

            if key in oid_mapping:
                attributes.append(x509.NameAttribute(oid_mapping[key], value))
            else:
                print(f"Warning: unknown attribute '{key}', skipping")
    
    return x509.Name(attributes)

def generate_autosigned_certificate(private_key, dname: str, days_valid=365):
    subject = parse_dname(dname)
    emmisor = subject

    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(emmisor)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(
            private_key=private_key,
            algorithm=hashes.SHA256()
        )
    )

    return certificate
    
def obtain_certificate_info(certificate):
    sha256_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    sha1_fingerprint = certificate.fingerprint(hashes.SHA1()).hex()

    return {
        'owner': certificate.subject.rfc4514_string(),
        'issuer': certificate.issuer.rfc4514_string(),
        'serial_number': hex(certificate.serial_number)[2:],
        'not_valid_before': certificate.not_valid_before_utc,
        'not_valid_after': certificate.not_valid_after_utc,
        'sha256': sha256_fingerprint,
        'sha1': sha1_fingerprint
    }