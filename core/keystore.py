import os
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption

def save_keystore_pkcs12(keystore_path: str, alias: str, private_key, certificate, password: str):
    alias_bytes = alias.encode('utf-8')
    pass_bytes = password.encode('utf-8')

    p12_data = pkcs12.serialize_key_and_certificates(
        name=alias_bytes,
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(pass_bytes)
    )

    with open(keystore_path, "wb") as f:
        f.write(p12_data)

    print(f"Keystore saved to {keystore_path}")
    print(f"Alias: {alias}"
    )

def load_keystore_pkcs12(keystore_path: str, password: str):
    if not os.path.exists(keystore_path):
        raise FileNotFoundError(f"Keystore not found: {keystore_path}")

    if os.path.getsize(keystore_path) == 0:
        return None, None, []
    
    pass_bytes = password.encode('utf-8')

    with open(keystore_path, "rb") as f:
        p12_data = f.read()

    private_key, certificate, cas = pkcs12.load_key_and_certificates(
        data=p12_data,
        password=pass_bytes
    )

    return private_key, certificate, cas

def delete_pkcs12_entry(keystore_path: str, alias: str, password: str):
    key, cert, cas = load_keystore_pkcs12(keystore_path, password)

    if key is None and cert is None and not cas:
        raise ValueError(f'Keystore {keystore_path} is empty.')

    
    pass_bytes = password.encode('utf-8')
    
    if cas:
        p12_data = pkcs12.serialize_key_and_certificates(
            name=None,
            key=None,
            cert=None,
            cas=cas,
            encryption_algorithm=pkcs12.BestAvailableEncryption(pass_bytes),
        )
        with open(keystore_path, 'wb') as f:
            f.write(p12_data)
    else:
        with open(keystore_path, 'wb') as f:
            f.write(b'')
    print(f"Deleted alias '{alias}' from {keystore_path}")    
    