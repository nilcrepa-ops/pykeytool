import argparse

def create_parser():
    parser = argparse.ArgumentParser(description="Keytool in python for key and certificate")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    parser_gen = subparsers.add_parser('genkeypair',help = "Generate a key pair")

    parser_gen.add_argument("-alias",required = True, help ="Alias for the key pair")
    parser_gen.add_argument("-keystore",required = True, help ="Keystore file")
    parser_gen.add_argument("-storepass",default = None, help ="Keystore password")
    parser_gen.add_argument("-keypass",default = None, help ="Key password")
    parser_gen.add_argument("-dname",default = None, help ="Distinguished name")
    parser_gen.add_argument("-keyalg",default = 'Rsa', help ="Key algorithm")
    parser_gen.add_argument("-keysize",default = 2048, help ="Key size")
    parser_gen.add_argument("-validity",default = 365, help ="Validity in days")

    parser_list = subparsers.add_parser("list", help ="List all keys in the keystore")
    parser_list.add_argument("-keystore",required = True, help ="Keystore file")
    parser_list.add_argument("-storepass",default = None, help ="Keystore password")
    parser_list.add_argument("-v",action="store_true", help="Print certificate details")

    return parser

