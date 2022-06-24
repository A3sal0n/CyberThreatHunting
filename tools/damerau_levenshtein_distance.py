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
import json
import getopt
from datetime import datetime
from lib.damerau_levenshtein import DamerauLevenshtein


def main(argv):
    startTime = datetime.now()
    tdist = ''
    ifile = ''
    ofile = ''

    try:
        opts, args = getopt.getopt(argv, "ht:i:o:", ["tdist=", "ifile=", "ofile="])
    except getopt.GetoptError:
        print 'damerau_levenshtein_distance.py -t <domains> -i <input file> -o <output file>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'damerau_levenshtein_distance.py -t <domains> -i <input file> -o <output file>'
            sys.exit()
        elif opt in ("-t", "--tdist"):
            tdist = arg
        elif opt in ("-i", "--ifile"):
            ifile = arg
        elif opt in ("-o", "--ofile"):
            ofile = arg

    lines = []
    try:
        f = open(ifile, 'r')
        lines = f.readlines()
        f.close()
    except IOError:
        print 'The file ' + ifile + ' was not found or cannot be opened!'
        print 'damerau_levenshtein_distance.py -t <domains> -i <input file> -o <output file>'
        sys.exit(2)

    items = []
    for line in lines:
        items.append(line.strip())

    dl = DamerauLevenshtein(tdist, items)

    res = dl.calc_distance_domains()

    if res is not None:
        try:
            f = open(ofile, 'w')
            for item in res:
                f.write(json.dumps(item) + '\n')
            f.close()
        except IOError:
            print 'The file ' + ofile + ' could not be created!'
            print 'damerau_levenshtein_distance.py -t <domains> -i <input file> -o <output file>'
            sys.exit(2)
    else:
        print 'No suspicious entries were found!'

    print 'Done!'
    print 'Your results have been saved to the file ', ofile
    print 'Time elapsed: ' + str(datetime.now() - startTime)
    print 'Have a nice day!'


if __name__ == "__main__":
    main(sys.argv[1:])
