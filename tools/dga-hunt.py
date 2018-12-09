#!/usr/bin/python

#Copyright (C) 2018  Leonardo Mokarzel Falcon
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>

import sys
from scapy.all import *
import getopt
from datetime import datetime
import sqlite3 as lite
import requests
import re
import math
from collections import Counter
import socket
import lib.gib_detect_train as gib
import pickle


def main(argv):
    startTime = datetime.now()
    source = ''
    ifile = ''
    ofile = ''
    domains = []

    try:
        opts, args = getopt.getopt(argv, "hs:i:o:", ["source=", "ifile=", "ofile="])
    except getopt.GetoptError:
        print('dga-hunt.py -s <csv/pcap> -i <input file> -o <output file>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('dga-hunt.py -s <csv/pcap> -i <input file> -o <output file>')
            sys.exit()
        elif opt in ("-s", "--source"):
            source = arg
        elif opt in ("-i", "--ifile"):
            ifile = arg
        elif opt in ("-o", "--ofile"):
            ofile = arg

    if not source or not ifile or not ofile:
        print('Wrong or incomplete input parameters!')
        print('dga-hunt.py -s <csv/pcap> -i <input file> -o <output file>')
        sys.exit()

    print('Generating and training Markov model')
    gib.train()

    print('Retrieving list of TLDs and Alexa top domains')
    tlds = get_tlds()
    topd = get_top_domains('shared/top_domains.sqlite')

    if source == 'csv':
        lines = []
        try:
            f = open(ifile, 'r')
            lines = f.readlines()
            f.close()
        except IOError:
            print('The file ' + ifile + ' was not found or cannot be opened!')
            print('dga-hunt.py -s <csv/pcap> -i <input file> -o <output file>')
            sys.exit(2)

        lines.pop(0)
        for line in lines:
            domain = line.strip()
            if domain not in domains:
                domains.append(domain.lower())
        domains = set(domains)
        res = find_bad_domains(topd, domains)
        if res is None:
            print('No suspicious domain were found. Congratulations!')
        else:
            f = open(ofile, 'w')
            for domain in res:
                f.write(domain + '\n')
            f.close()
    elif source == 'pcap':
        domains = get_pcap_domains(ifile, tlds)
        res = find_bad_domains(topd, domains)
        if res is None:
            print('No suspicious domain were found. Congratulations!')
        else:
            f = open(ofile, 'w')
            for domain in res:
                f.write(domain + '\n')
            f.close()

    else:
        print('Wrong or incomplete input parameters!')
        print('dga-hunt.py -s <csv/pcap> -i <input file> -o <output file>')
        sys.exit(2)

    print('Done!')
    print('Your results have been saved to the file ' + ofile)
    print('Time elapsed: ' + str(datetime.now() - startTime))
    print('Have a nice day!')


def get_tlds():
    tlds = []
    url = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt'
    try:
        r = requests.get(url)
    except requests.exceptions.ConnectionError:
        print('Connection error!\nCheck your network connection and try again')
        sys.exit(2)
    lines = r.text.split('\n')
    lines.pop(0)
    for line in lines:
        tld = line.strip()
        if tld:
            tlds.append(tld.lower())
    return set(tlds)


def get_top_domains(dbname):
    con = lite.connect(dbname)
    con.text_factory = str
    with con:
        cur = con.cursor()
        cur.execute("SELECT domain FROM domains")
        rows = cur.fetchall()
        domains = []
        if rows:
            for row in rows:
                domains.append(row[0].lower())
        else:
            pass
        return set(domains)


def get_pcap_domains(pcap_file, tlds):
    p = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
    domains = []
    try:
        packets = rdpcap(pcap_file)
    except IOError:
        print('Pcap file is not present or cannot be opened!')
        print('dga-hunt.py -s <csv/pcap> -i <input file> -o <output file>')
        sys.exit(2)
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.rstrip('.')
            query = query.lower()
            res = p.match(query)
            if res is not None:
                fields = query.split('.')
                if fields[-1] in tlds:
                    domains.append(fields[-2]+'.'+fields[-1])
    if len(domains) > 0:
        return set(domains)
    else:
        print('The pcap file provided does not contain relevant DNS requests.')
        print('Repeat your experiment and ensure that the relevant network traffic from the malware sample is captured.')
        print('dga-hunt.py -s <csv/pcap> -i <input file> -o <output file>')
        sys.exit(2)


def entropy(s):
    "Calculates the Boltzmann entropy of a string"
    l = float(len(s))
    return -sum(map(lambda a: (a / l) * math.log((a / l), 2), Counter(s).values()))


def find_bad_domains(topd, domains):
    model_data = pickle.load(open('shared/gib_model.pki', 'rb'))
    model_mat = model_data['mat']
    threshold = model_data['thresh']
    suspicious = []
    for domain in domains:
        if domain not in topd:
            #resolved = False
            #try:
            #    data = socket.gethostbyname(domain)
            #    resolved = True
            #except socket.gaierror:
            #    pass
            if (entropy(domain) > 3) and (gib.avg_transition_prob(domain, model_mat) < threshold):
                suspicious.append(domain)
    if len(suspicious) > 0:
        return suspicious
    else:
        return None


if __name__ == "__main__":
    main(sys.argv[1:])
