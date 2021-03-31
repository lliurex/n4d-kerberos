#!/usr/bin/env python3
from subprocess import Popen, PIPE
import argparse
from pathlib import Path
from sys import exit

def init_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
                usage="(%prog)s user host",
                description="utility to add host on keytab"
            )
    parser.add_argument("user")
    parser.add_argument("host")
    return parser

def main():
    parser = init_parser()
    args = parser.parse_args()
    
    keytab_path = "/run/{0}/keytab".format(args.user)
    
    if not Path(keytab_path).exists:
        exit(0)

    
    p = Popen("kadmin -p {principal} -k -t {keytab_path} -q 'ktrem -k /etc/krb5.keytab nfs/{host} all'".format(principal=args.user,keytab_path=keytab_path, host=args.host),shell=True).communicate()
    p = Popen("kadmin -p {principal} -k -t {keytab_path} -q 'ktadd -norandkey nfs/{host}'".format(principal=args.user,keytab_path=keytab_path, host=args.host),shell=True).communicate()
    exit(0)

if __name__ == "__main__":
    main()



