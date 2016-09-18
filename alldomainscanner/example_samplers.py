from dashie_sampler import DashieSampler
import requests
import random
import collections
import requests, json, simplejson, ast
from fractions import Fraction
from collections import OrderedDict
from math import *

URL= "http://127.0.0.1:8080/api/ssl/v1.0/getmetrics"
URL_VIOLATION = "https://scan.in.ft.com/violations.html"


def magic(numList): # [1,2,3]
    s = map(str, numList) # ['1','2','3']
    s = ''.join(s) # '123'
    s = int(s) # 123
    return s

# Percentage of compliant URL
class SynergySampler(DashieSampler):
    def __init__(self, *args, **kwargs):
        DashieSampler.__init__(self, *args, **kwargs)
        self._last = 0
        self.url = URL

    def name(self):
        return 'synergy'

    def sample(self):
        val = 1
        r = requests.get(self.url, verify=False)


        if r.status_code == 200:
            output_scan = simplejson.loads(simplejson.dumps(r.json()))
            compliant = output_scan["totalscanned"][0]["nb_scanned"]
            total = output_scan["totalscanned"][2]["nb_scanned"]
            try:
                val = round(compliant, 1) / total
            except ZeroDivisionError:
                pass
        percent = floor(val * 100)

        s = {'value':  percent,
            'current': percent,
             'last': self._last}
        self._last = s['current']
        return s

# List of non compliant URL
class BuzzwordsSampler(DashieSampler):
    def name(self):
        return 'buzzwords'

    def sample(self):
        url = URL
        dico = {}
        items = {}
        r = requests.get(url, verify=False)

        if r.status_code == 200:
            output_scan = simplejson.loads(simplejson.dumps(r.json()))
            # reformmating to a proper dico
            for line in output_scan["getnotcompliant"]:
                mykey =  line["scan_url"]
                myvalue = line["no_violation"]
                dico[''.join(mykey)] = [ myvalue, URL_VIOLATION ]
            dico_sorted = OrderedDict(sorted(dico.items(), key=lambda t: t[1], reverse=True)[:10])

            items = [{'label': keys, 'value': values[0], 'location': values[1]} for keys, values in dico_sorted.iteritems()]
        return {'items': items}

# Total URL scanned
class WebsiteUpSampler(DashieSampler):
    def __init__(self, *args, **kwargs):
        DashieSampler.__init__(self, *args, **kwargs)
        self._last = 0
        self.url = URL 

    def name(self):
        return 'website_up'

    def sample(self):
        dico = {}
        items = {}
        s = {}
        r = requests.get(self.url, verify=False)

        if r.status_code == 200:
            output_scan = simplejson.loads(simplejson.dumps(r.json()))
            total = output_scan["totalscanned"][2]["nb_scanned"]
            s = {"text":total}
        return s

# Last URL scanned
class LastScannedURL(DashieSampler):
    def __init__(self, *args, **kwargs):
        DashieSampler.__init__(self, *args, **kwargs)
        self._last = 0
        self.url = URL

    def name(self):
        return 'lastscanned'

    def sample(self):
        dico = {}
        items = {}
        s = {}
        r = requests.get(self.url, verify=False)

        if r.status_code == 200:
            output_scan = simplejson.loads(simplejson.dumps(r.json()))
            try:
                total = output_scan["lastscanned"][0]["scan_url"]
            except IndexError:
                total = "No URL scanned yet"
            s = {"text":total}
        return s
