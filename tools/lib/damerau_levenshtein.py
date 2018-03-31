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
import sqlite3 as lite
from pyxdameraulevenshtein import normalized_damerau_levenshtein_distance


class DamerauLevenshtein:
    def __init__(self, tdist, data):
        self.tdist = tdist
        self.data = set(data)
        self.top_domains_db = 'shared/top_domains.sqlite'
        self.top_domains = set()

        if (tdist == 'domains'):
            self.load_top_domains()
        else:
            print 'Unknown option:', tdist
            print 'damerau_levenshtein_distance.py -t <domain> -i <input file> -o <output file>'
            sys.exit(2)

    def calc_distance_domains(self):
        not_in_top = []
        output = []
        for item in self.data:
            if item not in self.top_domains:
                not_in_top.append(item)

        for item in not_in_top:
            entry = {item: {}}
            flag = False
            for td in self.top_domains:
                dist = normalized_damerau_levenshtein_distance(item, td)
                if 0 < dist < 0.2:
                    entry[item][td] = dist
                    flag = True
            if flag is True:
                output.append(entry)
        if len(output) > 0:
            return output
        else:
            return None

    def load_top_domains(self):
        con = lite.connect(self.top_domains_db)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT domain FROM domains")
            rows = cur.fetchall()
            domains = []
            if rows:
                for i in range(10000):
                    domains.append(rows[i][0])
            else:
                pass
        self.top_domains = set(domains)
