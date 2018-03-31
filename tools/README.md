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
