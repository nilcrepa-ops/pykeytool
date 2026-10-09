from core.crypto import obtain_certificate_info
from core.keystore import load_keystore_pkcs12
import sys
import getpass
from cli import *
from core.crypto import *
from core.keystore import *

def execute_genkeypair(args):
    password = args.storepass
    if not password:
        password = getpass.getpass("Enter keystore password: ")
        if len(password) == 0:
            print("Password cannot be empty")
            sys.exit(1)
        elif len(password) < 6:
            print("Password must be at least 6 characters long")
            sys.exit(1)

    print(f'Generating key pair {args.keyalg} of {args.keysize} bits...')
    private_key = generate_rsa_key(args.keysize)

    print(f'Generating self-signed certificate...')
    dname = args.dname if args.dname else f'CN={args.alias}, O=PracticaDAM, C=ES'
    certificate = generate_autosigned_certificate(private_key, dname, args.validity)

    print(f'Packaging and saving in {args.keystore} with alias {args.alias}')
    try:
        save_keystore_pkcs12(
            keystore_path=args.keystore,
            alias=args.alias,
            private_key=private_key,
            certificate=certificate,
            password=password
        )
    except Exception as e:
        print(f'Error saving keystore: {e}')
        sys.exit(1)

def execute_list(args):
    password = args.storepass
    if not password:
        password = getpass.getpass("Enter keystore password: ")
        if len(password) == 0:
            print("Password cannot be empty")
            sys.exit(1)
        elif len(password) < 6:
            print("Password must be at least 6 characters long")
            sys.exit(1)
    
    try:
        key, cert, cas = load_keystore_pkcs12(args.keystore, password)
    except Exception as error:
        print(f"Error loading keystore: {error}")
        sys.exit(1)
    
    if args.v:
        info = obtain_certificate_info(cert)
        print(f'Owner: {info['owner']}')
        print(f'Issuer: {info['issuer']}')
        print(f'Serial number: {info['serial_number']}')
        print(f'Not valid before: {info['not_valid_before']}')
        print(f'Not valid after: {info['not_valid_after']}')
        print(f'SHA1 fingerprint: {info['sha1']}')
        print(f'SHA256 fingerprint: {info['sha256']}')

def main():
    parser = create_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    if args.command == "genkeypair":
        execute_genkeypair(args)
    elif args.command == "list":
        execute_list(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()