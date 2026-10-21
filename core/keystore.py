import os
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption

class PKCS12KeyStoreBuilder:
    def __init__(self):
        self._key = None
        self._cert = None
        self._name = None
        self._additional_certs = []

    def set_key_and_certificates(self, key, cert, name: bytes | str | None = None):
        if isinstance(cert, pkcs12.PKCS12Certificate):
            self._key = key
            self._cert = cert.certificate
            self._name = cert.friendly_name
            return self
        if isinstance(name, str):
            name = name.encode('utf-8')
        self._key = key
        self._cert = cert
        self._name = name
        return self

    def add_certificate(self, cert, name: bytes | str | None = None):
        if isinstance(cert, pkcs12.PKCS12Certificate):
            self._additional_certs.append(cert)
            return self
        if isinstance(name, str):
            name = name.encode('utf-8')
        pkcs12_cert = pkcs12.PKCS12Certificate(cert, name)
        self._additional_certs.append(pkcs12_cert)
        return self

    def build(self, password: bytes | str) -> bytes:
        if isinstance(password, str):
            password = password.encode('utf-8')
        return pkcs12.serialize_key_and_certificates(
            name=self._name,
            key=self._key,
            cert=self._cert,
            cas=self._additional_certs if self._additional_certs else None,
            encryption_algorithm=BestAvailableEncryption(password)
        )

pkcs12.PKCS12KeyStoreBuilder = PKCS12KeyStoreBuilder

def _pkcs12_iter(self):
    cert = self.cert.certificate if self.cert else None
    cas = [c.certificate for c in self.additional_certs]
    yield self.key
    yield cert
    yield cas

pkcs12.PKCS12KeyAndCertificates.__iter__ = _pkcs12_iter
pkcs12.PKCS12KeyAndCertificates.key_and_certificates = property(lambda self: self)


def save_keystore_pkcs12(keystore_path: str, alias: str, private_key, certificate, password: str):
    alias_bytes = alias.encode('utf-8')
    pass_bytes = password.encode('utf-8')

    builder = pkcs12.PKCS12KeyStoreBuilder()

    if os.path.exists(keystore_path) and os.path.getsize(keystore_path) > 0:
        with open(keystore_path, "rb") as f:
            p12_data = f.read()
        existing_keystore = pkcs12.load_pkcs12(p12_data, pass_bytes)

        if existing_keystore.cert:
            builder.add_certificate(
                existing_keystore.cert.certificate,
                existing_keystore.cert.friendly_name
            )
        for add_cert in existing_keystore.additional_certs:
            builder.add_certificate(
                add_cert.certificate,
                add_cert.friendly_name
            )

    builder.set_key_and_certificates(
        key=private_key,
        cert=certificate,
        name=alias_bytes
    )

    p12_data = builder.build(pass_bytes)

    with open(keystore_path, "wb") as f:
        f.write(p12_data)

    print(f"Keystore saved to {keystore_path}")
    print(f"Alias: {alias}")


def load_keystore_pkcs12(keystore_path: str, password: str):
    if not os.path.exists(keystore_path):
        raise FileNotFoundError(f"Keystore not found: {keystore_path}")

    if os.path.getsize(keystore_path) == 0:
        return pkcs12.PKCS12KeyAndCertificates(None, None, [])

    pass_bytes = password.encode('utf-8')

    with open(keystore_path, "rb") as f:
        p12_data = f.read()

    keystore = pkcs12.load_pkcs12(
        data=p12_data,
        password=pass_bytes
    )

    return keystore


def delete_pkcs12_entry(keystore_path: str, alias: str, password: str):
    keystore = load_keystore_pkcs12(keystore_path, password)

    if not keystore.cert and not keystore.key and not keystore.additional_certs:
        raise ValueError(f'Keystore {keystore_path} is empty.')

    pass_bytes = password.encode('utf-8')
    alias_bytes = alias.encode('utf-8')

    found = False
    new_key = None
    new_cert = None
    new_name = None
    new_cas = []

    if keystore.cert:
        if keystore.cert.friendly_name == alias_bytes:
            found = True
        else:
            new_key = keystore.key
            new_cert = keystore.cert.certificate
            new_name = keystore.cert.friendly_name

    for add_cert in keystore.additional_certs:
        if add_cert.friendly_name == alias_bytes:
            found = True
        else:
            new_cas.append(add_cert)

    if not found:
        raise ValueError(f"Alias '{alias}' not found in {keystore_path}")

    if new_cert is None and new_cas:
        promoted = new_cas.pop(0)
        new_cert = promoted.certificate
        new_name = promoted.friendly_name

    if new_cert or new_key or new_cas:
        p12_data = pkcs12.serialize_key_and_certificates(
            name=new_name,
            key=new_key,
            cert=new_cert,
            cas=new_cas if new_cas else None,
            encryption_algorithm=BestAvailableEncryption(pass_bytes),
        )
        with open(keystore_path, 'wb') as f:
            f.write(p12_data)
    else:
        with open(keystore_path, 'wb') as f:
            f.write(b'')

    print(f"Deleted alias '{alias}' from {keystore_path}")