#!/usr/bin/env python3
'''
This script is used to diagnose DNS issues.

'''

import argparse
import dns.resolver
import dns.query
import dns.zone
import dns.reversename
import dns.rdatatype
import dns.rdataclass
import dns.exception
import yaml
import time
import json
import os
import sys

VERBOSE = False

def get_args():
    parser = argparse.ArgumentParser(description='DNS Diagnostics')
    parser.add_argument('config', help='YAML config file')
    # --verbose
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    return parser.parse_args()

def load_config(config_file):
    with open(config_file) as f:
        return yaml.safe_load(f)

def store_report(details):
    fname = 'dnsdiag-report-{}.txt'.format(time.strftime('%Y%m%d-%H%M%S'))
    # if file exists write -NNN to filename
    seq = 0
    while os.path.exists(fname):
        fname = 'dnsdiag-report-{}-{}.txt'.format(time.strftime('%Y%m%d-%H%M%S'), str(seq).zfill(3))
        seq += 1

    header = f'DNS Diagnostics Report - {time.strftime("%Y-%m-%d %H:%M:%S")}\n'
    with open(fname, 'w') as f:
        f.write(details)
    print(f'Report saved to {fname}')
    print(details)

def rdtype_to_text(rdtype):
    '''
    Stub function to convert rdtype to text
    '''
    return dns.rdatatype.to_text(rdtype);
        


class DNSDiag:
    def __init__(self, config):
        self.config = config
        # iterate over dns tests, and if 

    def test_resolver(self, resolver):
        '''
        Make dummy . NS query to test resolver
        '''
        valid_answers = ['a.root-servers.net.', 'b.root-servers.net.', 'c.root-servers.net.', 'd.root-servers.net.', 'e.root-servers.net.', 'f.root-servers.net.', 'g.root-servers.net.', 'h.root-servers.net.', 'i.root-servers.net.', 'j.root-servers.net.', 'k.root-servers.net.', 'l.root-servers.net.', 'm.root-servers.net.']
        try:
            query = dns.message.make_query('.', dns.rdatatype.NS)
            if resolver['type'] == 'tcp':
                response = dns.query.tcp(query, resolver['ip'], timeout=10)
            else:
                response = dns.query.udp(query, resolver['ip'], timeout=10)
            for answer in response.answer:
                for rrset in answer:
                    if rrset.rdtype == dns.rdatatype.NS and rrset.to_text() in valid_answers:
                        return True
        except dns.exception.DNSException as e:
            print(e)

        return False
    
    def test_all_resolvers(self):
        resolvers = self.config.get('resolvers', [])
        self.config['tested_resolver'] = None
        # verify resolvers and pick first working resolver
        for resolver in resolvers:
            try:
                if self.test_resolver(resolver):
                    self.config['tested_resolver'] = resolver
                    break
                break
            except dns.exception.DNSException as e:
                print(e)
                continue
        
        if VERBOSE:
            if self.config['tested_resolver']:
                print('Using resolver: {}'.format(self.config['tested_resolver']))
            else:
                print('No working resolver found')
        
        if not self.config['tested_resolver']:
            raise Exception('No working resolver found')
    
    def name2ip(self, domain):
        retanswer = []
        attempts = 10
        while True:
            try:
                dnssec_opt = self.config['tested_resolver'].get('dnssec', False)
                if VERBOSE:
                    print(f'Querying {domain} with DNSSEC: {dnssec_opt}')
                query = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=dnssec_opt)
                if self.config['tested_resolver']['type'] == 'tcp':
                    response = dns.query.tcp(query, self.config['tested_resolver']['ip'], timeout=10)
                else:
                    response = dns.query.udp(query, self.config['tested_resolver']['ip'], timeout=10)
                for answer in response.answer:
                    for rrset in answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            retanswer.append(rrset.to_text())
                break
            except dns.exception.DNSException as e:
                print(f"Error: {e}, retrying...")
                attempts -= 1
                if attempts == 0:
                    break
            except Exception as e:
                print(f"Error: {e}")
                break

        if not retanswer:
            if dnssec_opt:
                # verify EDNS option in answer
                if response.options:
                    print(f'Options: {response.options.to_text()}')
                        
            raise Exception(f'No A record found for {domain} at {self.config["tested_resolver"]["ip"]}')
        
        return retanswer
    
    '''
    def get_authoritative_nameservers(self, domain, ns_servers):
        try:
            query = dns.message.make_query(domain, dns.rdatatype.NS)
            if self.config['tested_resolver']['type'] == 'tcp':
                response = dns.query.udp(query, ns_servers[0], timeout=10)
            else:
                response = dns.query.tcp(query, ns_servers[0], timeout=10)

            for ns in response.answer:
                for rrset in ns:
                    print(rrset)
        except dns.exception.DNSException as e:
            print(e)
    '''

    def test_dns_query(self, test):
        '''
        We have query_name (str), query_types (list), nameservers (list)
        '''
        query_name = test['query_name']
        query_types = test['query_types']
        nameservers = test['nameservers']
        q_proto = test.get('query_protocol', 'udp')
        nameservers_ips = []
        # convert nameservers to nameservers_ips
        if VERBOSE:
            print('Converting nameservers to IPs...')
        for ns in nameservers:
            if VERBOSE:
                print(f'Converting {ns} to IP...')
            ip = self.name2ip(ns)
            nameservers_ips.extend(ip)
        
        if VERBOSE:
            print('Nameservers IPs: {}'.format(nameservers_ips))

        answers = {}
        # store nameserver names and ips in answers and sort
        answers['nameservers'] = {}
        answers['nameservers_ips'] = {}
        answers['nameservers']['names'] = nameservers
        answers['nameservers_ips']['ips'] = nameservers_ips
        answers['nameservers']['names'].sort()
        answers['nameservers_ips']['ips'].sort()

        # for query_types on each of nameservers_ips and save in array of answers
        for query_type in query_types:
            answers[query_type] = {}
            for ns_ip in nameservers_ips:
                try:
                    answers[query_type][ns_ip] = []
                    dnssec_opt = self.config['tested_resolver'].get('dnssec', False)
                    query = dns.message.make_query(query_name, query_type, want_dnssec=dnssec_opt)
                    if VERBOSE:
                        print(f'Querying {query_name} {query_type} on {ns_ip}...')
                    
                    if q_proto == 'tcp':
                        response = dns.query.tcp(query, ns_ip, timeout=10)
                    else:
                        response = dns.query.udp(query, ns_ip, timeout=10)
                    for answer in response.answer:
                        for rrset in answer:
                            rrinfo = rdtype_to_text(rrset.rdtype)
                            rrinfo += ' ' + rrset.to_text()
                            print(f'Adding {rrinfo} to answers')
                            answers[query_type][ns_ip].append(rrinfo)
                except dns.exception.DNSException as e:
                    print(e)
        
        if VERBOSE:
            print(answers)
        
        # now verify if all answers for each query same across all nameservers
        for query_type in query_types:
            print(f'Verifying query: {query_name} {query_type}')
            # do we have answers >= 1?
            if not answers[query_type]:
                print(f'No answers found for {query_name} {query_type}')
                continue
            elif VERBOSE:
                print(f'Answers found for {query_name} {query_type}: {len(answers[query_type])}')
            answers[query_type][nameservers_ips[0]].sort()
            for ns_ip in nameservers_ips:
                # sort arrays
                answers[query_type][ns_ip].sort()
                if answers[query_type][ns_ip] != answers[query_type][nameservers_ips[0]]:
                    report = f'Inconsistent nameservers results for {query_name} {query_type} on {ns_ip}\n'
                    report += f'Reference nameserver: {nameservers_ips[0]}\nExpected:\n'
                    for entry in answers[query_type][nameservers_ips[0]]:
                        report += f'{entry}\n'
                    #report += f'Expected:\n{answers[query_type][nameservers_ips[0]]}\n'
                    report += f'Got:\n'
                    #report += f'Got:\n{answers[query_type][ns_ip]}\n'
                    for entry in answers[query_type][ns_ip]:
                        report += f'{entry}\n'
                    store_report(report)

            if VERBOSE:
                print(f'All nameservers returned same results for {query_name} {query_type}')
            # make sure answers always sorted and consistent for comparison

        # sort answers
        answers = dict(sorted(answers.items()))

        stored_fname = f'dnsdiag-report-{test["name"]}.json'
        # if file doesn't exist, create it, and store results
        if not os.path.exists(stored_fname):
            with open(stored_fname, 'w') as f:
                json.dump(answers, f)

        # compare stored previous results (json) with current results
        # if not same, report, and store new data
        with open(stored_fname) as f:
            prev_results = json.load(f)
            if prev_results != answers:
                report = f'Mismatch for {query_name} with previous results\n'
                report += f'Expected:\n{prev_results}\n'
                report += f'Got:\n{answers}\n'
                store_report(report)
                # rename old results with timestamp
                new_fname = f'dnsdiag-report-{test["name"]}-{time.strftime("%Y%m%d-%H%M%S")}.json'
                os.rename(stored_fname, new_fname)
                # store new results
                with open(stored_fname, 'w') as f:
                    json.dump(answers, f)
            else:
                if VERBOSE:
                    print(f'Previous results match for {query_name}')

    def run(self):
        tests = self.config.get('dns', [])
        for test in tests:
            if test['type'] == 'query':
                if VERBOSE:
                    print('Testing query: {}'.format(test['query_name']))
                self.test_dns_query(test)

def main():
    global VERBOSE
    args = get_args()
    if args.verbose:
        VERBOSE = True

    config = load_config(args.config)
    dnsdiag = DNSDiag(config)
    dnsdiag.test_all_resolvers()
    dnsdiag.run()



if __name__ == '__main__':
    main()