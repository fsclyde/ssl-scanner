__author__ = "Clyde Fondop"
# -*- coding: utf-8 -*-
#!/usr/bin/env python
#title           :scanner.py
#description     :SSL SCANNER OF ALL URL
#author          : clyde
#date            :20110930
#version         :0.1
#usage           :python2 scanner.py
#notes           :
#python_version  : 2.7
#==============================================================================
#
#
#
# Import the modules needed to run the script.
import config, ast
from config import *
import requests
import datetime, json, simplejson
import shutil, errno, argparse
from datetime import datetime

MyLogger = Logger()
import time

class URLScanner:

    def __init__(self):
        self.url = config.URL
        self.httpcode = 500
        self.description_text = "All domain SSL scanner"

    # Argurments
    def createParser(self):
        parser = argparse.ArgumentParser(description=self.description_text)
        parser.add_argument("-s", "--skipcache", choices=['true','false'], default='true', action="store", required=False, help='Cache busting: True / False default: True')
        parser.add_argument("-v", "--showdetails", choices=['true','false'], default='false', action="store", required=False, help='Getting more information True / False default: False')
        return parser

    # Open file
    def open_file(self, input_file):
        try:
            fh = open(input_file, 'r')
            output_file = fh.read().splitlines()
            fh.close()
        except IOError:
            message = config.message_no_file
            MyLogger.write_log(message)
            print(message)
            exit(1)

        return output_file

    # Perform scan
    def scan_entry(self, input_value, skipcache, showdetails):
        scan_value = 0
        compliance = ""
        output_scan = {}

        # if Error when scanning URL
        try:
            if skipcache == "true" and showdetails == "false":
                r = requests.post(self.url, json = {"url":""+input_value+"","skipcache":"true"})
            elif showdetails == "true" and skipcache == "true":
                r = requests.post(self.url, json={"url": "" + input_value + "", "showdetails": "true","skipcache":"true"})
            elif showdetails == "true" and skipcache == "false":
                r = requests.post(self.url,json={"url": "" + input_value + "", "showdetails": "true"})
            else:
                r = requests.post(self.url, json={"url": "" + input_value + ""})

        except requests.exceptions.Timeout:
            message = config.message_timeout
            scan_value = 1
            self.httpcode = 308
            print(message)

        except requests.exceptions.TooManyRedirects:
            message = config.message_redirects
            scan_value = 1
            self.httpcode = 308
            print(message)

        except requests.exceptions.RequestException:
            message = config.message_req_exception
            scan_value = 1
            self.httpcode = 500
            time.sleep(5)
            MyLogger.write_log(message)
            print(message)

        if scan_value == 0:
            # Opening the result
            self.httpcode = r.status_code
            try:
                output_scan = simplejson.loads(simplejson.dumps(r.json()))
            except ValueError:
                message = config.message_req_exception
                MyLogger.write_log(message)
                print(message)
                #exit(1)

            # if Error when retriving the data
            try:
                compliance = output_scan[0]["status"]
            except KeyError:
                error_message = config.message_req_exception
                MyLogger.write_log("error=" + error_message + " " + "url=" + input_value)
                time.sleep(1)

            except IndexError:  
                error_message = config.message_req_exception
                MyLogger.write_log("error=" + error_message + " " + "url=" + input_value)
                time.sleep(1)


        return self.httpcode, compliance, output_scan


#################################################
#
# START
#
#################################################

if __name__ == '__main__':
    total = 0
    nb_notcompliant = 0

    MyURLScanner = URLScanner()
    parser = MyURLScanner.createParser()
    args = parser.parse_args()

    report_file = MyURLScanner.open_file(config.DOMAIN)

    # Reading the file
    for row in report_file:

        httpcode, compliance, output_scan = MyURLScanner.scan_entry(row, args.skipcache, args.showdetails)
        print httpcode, compliance, row
				



