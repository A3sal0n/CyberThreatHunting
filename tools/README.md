## Collection of custom scripts for hunting

### Damerau Levenshtein Distance

This script allows detecting domains which have names that are very close to well-known domains. This is a common strategy used by attackers to trick users and make them click in phishing emails, or to hide in plain sight the traffic of malware to C&C servers, etc.

#### Requirements

This code requires 2.7 or Python 3.4+ and the libraries [pyxDamerauLevenshtein](https://pypi.python.org/pypi/pyxDamerauLevenshtein) and [NumPy](http://www.numpy.org/)


#### Usage

`damerau_levenshtein_distance.py -t <domains> -i <input file> -o <output file>`

Example:

`python damerau_levenshtein_distance.py -t domains -i target_domains.csv -o results.txt`

As input the script expects a 1 column list of the target domains to be evaluated.

Sample input:

`cloudflare.com`

`github.com`

`hello.com`

`gooogle.com`

`linkedin.com`

`faceboook.com`

`gmail.com`

`random123456789.com`

Sample output:

`{"gooogle.com": {"google.com": 0.09090909361839294, "google.cm": 0.1818181872367859}}`

`{"faceboook.com": {"facebook.com": 0.07692307978868484}}`

### Hunting on Bro DNS logs using Isolation Forest

This script allows detecting outliers in Bro DNS logs using the Isolation Forest algorithm as implemented in the Python library [scikit-learn](http://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html). This method does not detect "evil" by default but it can help to identify rare events within a large number of DNS requests. Some of these rare events may be malicious in nature and could be spotted visually by analysts having a good knowledge of the environment they're defending.

#### Requirements

This code requires Python 2.7 and the libraries below.

- bat (https://github.com/Kitware/bat)
- pandas (https://pandas.pydata.org/)
- sklearn (http://scikit-learn.org/stable/)
- numpy (http://www.numpy.org/)

The Bro DNS log records must have json format (https://www.bro.org/sphinx/scripts/policy/tuning/json-logs.bro.html)

#### Usage

`bro-dns-iforest.py -i <Bro DNS file>`

The script saves the results in two different files: outliers.json and kmeans-clusters.json. The first file contains all the outlier events detected and the second the same events but clustered using the algorithm KMeans.
