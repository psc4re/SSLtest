#!/usr/bin/env python
# inspired by 'TrullJ'
__author__ = 'Prajwal Panchmahalkar'
import sys
import json
import time
import requests


def sendReq(payload={}):
    url = 'https://api.ssllabs.com/api/v2/analyze'
    try:
        response = requests.get(url, params=payload).json()
        return(response)
    except requests.exception.RequestException as e:
        print(e)
        exit(1)


def scanHost(host):
    r = {}
    payload = {'host': host, 'publish': 'off', 'startNew': 'off', 'all': 'done', 'ignoreMismatch': 'on'}
    results = sendReq(payload)
    payload.pop('startNew')
    interesting_tests = ['poodle', 'poodleTls', 'supportsRc4', 'vulnBeast', 'logjam', 'heartbleed', 'openSSLLuckyMinus20', 'protocols']
    while results['status'] != 'READY' and results['status'] != 'ERROR':
        time.sleep(30)
        results = sendReq(payload)
    checkdata = results
    for each in checkdata['endpoints']:
        if 'Ready' not in each['statusMessage']: continue
        row = each['ipAddress']
        r.update({row: [{'IP Address': row}]})
        r[row].append({'Grade': each['grade']})
        for testtype in interesting_tests:
            r[row].append({testtype.upper(): each['details'][testtype]})
    return(r)


if __name__ == '__main__':
    if(len(sys.argv) != 2):
        print('SSLtest, %s\n\t[!] Usage eg.: python %s www.google.com' % (__author__, __file__))
        exit()
    output = 'json'  # Optional JSON output - leave blank for key/value pair.
    results = scanHost(sys.argv[1])
    if output == 'json':
        print(json.dumps(results, indent=2))
        exit()
    for line in results:
        r = []
        for x in results[line]:
            data, value = x.items()[0]
            r.append('{} = {}'.format(data, value))
        print(', '.join(r))
