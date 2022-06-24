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
import getopt
import json
import math
from datetime import datetime
from bat import dataframe_to_matrix
import pandas as pd
from sklearn.ensemble import IsolationForest
from collections import Counter
import numpy as np
from sklearn.cluster import KMeans
import warnings


def ttl_avg(ttls):
    sum = 0
    for ttl in ttls:
        sum += ttl
    return sum/len(ttls)


def string_encode(data):
    alphabet = '0123456789abcdefghijklmnopqrstuvwxyz.: '
    char_to_int = dict((c, i) for i, c in enumerate(alphabet))
    integer_encoded = [char_to_int[char.decode("ascii")] for char in data]
    encoded = ""
    for n in integer_encoded:
        encoded += str(n)
    return int(encoded)


def entropy(s):
    "Calculates the Boltzmann entropy of a string"
    l = float(len(s))
    return -sum(map(lambda a: (a / l) * math.log((a / l), 2), Counter(s).values()))


def select_fields(data):
    output = []
    selected = []
    for i in range(len(data)):
        try:
            row = {}
            if '.local' not in data[i]['query']:
                row['id.resp_p'] = int(data[i]['id.resp_p'])
                row['rtt'] = int(float(data[i]['rtt']) * 1000)
                row['q_length'] = len(data[i]['query'])
                row['q_entropy'] = entropy(data[i]['query'])
                row['qclass'] = int(data[i]['qclass'])
                row['qtype'] = int(data[i]['qtype'])
                row['rcode'] = int(data[i]['rcode'])
                ttls = data[i]['TTLs']
                row['ttl_avg'] = ttl_avg(ttls)
                output.append(row)
                selected.append(i)
        except KeyError:
            pass
    return output, selected


def main(argv):
    startTime = datetime.now()

    print 'Starting...\n'
    
    ifile = None
    cont = None

    try:
        opts, args = getopt.getopt(argv, "hi:c:", ["ifile=", "cont=",])
    except getopt.GetoptError:
        print 'Check your input parameters'
        print 'bro-dns-ml-hunt.py -i <input Bro DNS file> -c <contamination>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'bro-dns-ml-hunt.py -i <input Bro DNS file> -c <contamination>'
            sys.exit()
        elif opt in ("-i", "--ifile"):
            ifile = arg
        elif opt in ("-c", "--cont"):
            cont = float(arg)

    if not ifile:
        print 'A Bro log file must be provided as input'
        print 'bro-dns-ml-hunt.py -i <input Bro DNS file> -c <contamination>'
        sys.exit(2)

    if not cont:
        print 'Using default contamination value: 0.1'
        cont = 0.2

    rng = np.random.RandomState(42)

    # Loading target data set
    f = open(ifile, 'r')
    lines = f.readlines()
    f.close()

    data = []
    for line in lines:
        data.append(json.loads(line.strip()))

    original_data = data

    target_data, srows = select_fields(original_data)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # Create pandas dataframe

        bro_target_df = pd.DataFrame.from_dict(target_data, orient='columns')

        to_matrix = dataframe_to_matrix.DataFrameToMatrix()

        bro_target_matrix = to_matrix.fit_transform(bro_target_df)

        # Train using the Isolation Forest model
        iForest = IsolationForest(max_samples=100, contamination=cont, random_state=rng, verbose=False)
        iForest.fit(bro_target_matrix)

        # Get predictions
        outliers = iForest.predict(bro_target_matrix)

        # Save all outliers
        f = open('outliers.json', 'w')
        for i in range(len(outliers)):
            if outliers[i] == -1:
                f.write(json.dumps(original_data[srows[i]]) + '\n')
        f.close()

        # Isolate outliers
        odd_df = bro_target_df[outliers == -1]

        # Explore outliers with the help from KMeans
        odd_matrix = to_matrix.fit_transform(odd_df)
        num_clusters = min(len(odd_df), 4)  # 4 clusters unless we have less than 4 observations
        odd_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)

        # Group the dataframe by cluster
        cluster_groups = odd_df[['cluster']].groupby('cluster')

        # Save all outliers per cluster
        f = open('kmeans-clusters.json', 'w')
        for key, group in cluster_groups:
            f.write('#Cluster {:d}: {:d} observations'.format(key, len(group)) + '\n')
            np_matrix = group.to_records()
            for item in np_matrix:
                f.write(json.dumps(original_data[srows[item[0]]]) + '\n')
        f.close()

    print '\nDone!'
    print 'Your results have been saved to the files outliers.json and kmeans-clusters.json'
    print 'Time elapsed: ' + str(datetime.now() - startTime)
    print 'Have a nice day!'


if __name__ == "__main__":
    main(sys.argv[1:])
