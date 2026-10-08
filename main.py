import sys
from cli import crear_parser

def main():
    parser = crear_parser()
    
    args = parser.parse_args()

    if args.command == "genkeypair":
        print(f'You selected genkeypair command')
        print(f'Alias: {args.alias}')
        print(f'Keystore: {args.keystore}')
        print(f'Storepass: {args.storepass}')
        print(f'Keypass: {args.keypass}')
        print(f'Dname: {args.dname}')
        print(f'Keyalg: {args.keyalg}')
        print(f'Keysize: {args.keysize}')
        print(f'Validity: {args.validity}')
    else:
        parser.print_help()

if __name__ == "__main__":
    main()