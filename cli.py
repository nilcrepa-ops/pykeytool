import argparse

def create_parser():
    parser = argparse.ArgumentParser(
        prog = 'pykeytool',
        description="Keytool in python for key and certificate",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        add_help= False
        )

    parser.add_argument('--help', '-h', '-help', action = 'help', help = 'Show the help message')

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

    parser_export = subparsers.add_parser('exportcert', help = 'Export certificate')
    parser_export.add_argument('-alias', required = True, help = 'Alias of the entry to export')
    parser_export.add_argument('-keystore', required = None, default = None, help = 'Keystore fiel path')
    parser_export.add_argument('-file', required = True, help = 'Certificate file path')
    parser_export.add_argument('-storepass', required = None, default = None, help = 'Store password')
    parser_export.add_argument('-keypass', required = None, default = None, help = 'Key password')
    parser_export.add_argument('-rfc', action = 'store_true', help = 'Export in RFC1422 format')

    parser_print = subparsers.add_parser('printcert', help = 'Print certification file content')
    parser_print.add_argument('-file', required = True, help = 'Certificate file path')
    parser_print.add_argument('-v', action = 'store_true', help = 'Print certificate details')

    parser_delete = subparsers.add_parser('delete', help = 'Delete entry')
    parser_delete.add_argument('-keystore', required = True, help = 'Keystore file')
    parser_delete.add_argument('-storepass', required = None, default = None, help = 'Store password')
    parser_delete.add_argument('-alias', required = True, help = 'Alias of the entry to delete')

    parser_certreq = subparsers.add_parser('certreq', help = 'Generate a CSR')
    parser_certreq.add_argument('-alias', required = True, help = 'Alias of the entry to generate CSR')
    parser_certreq.add_argument('-keystore', required = True, help = 'Keystore file')
    parser_certreq.add_argument('-storepass', required = None, default = None, help = 'Store password')
    parser_certreq.add_argument('-sigalg', default = 'SHA256withRSA', help = 'Signature algorithm')
    parser_certreq.add_argument('-file', required = True, help = 'CSR file path')
    
    return parser

