__author__ = "Clyde Fondop"
# -*- coding: utf-8 -*-
# !/usr/bin/env python
# title           :scanner.py
# description     :SSL SCANNER OF ALL ULR
# author          : clyde
# date            :20110930
# version         :0.1
# usage           :python2 scanner.py
# notes           :
# python_version  :2.7
# ==============================================================================
#
#
#
# Import the modules needed to run the script.
import config, ast
from config import *
import requests
import datetime, json, simplejson
import shutil, errno, argparse, sys
from datetime import datetime

import threading
import Queue
import commands
import time

exitFlag = 0
MyLogger = Logger()
URL_LIST = {}
DICO_DOMAIN = {}
#################################################


class URLScanner:
    def __init__(self):
        self.url = config.URL
        self.httpcode = 500
        self.description_text = "All domain SSL scanner"

    # Argurments
    def createParser(self):
        parser = argparse.ArgumentParser(description=self.description_text)
        parser.add_argument("-s", "--skipcache", choices=['true', 'false'], default='true', action="store",
                            required=False, help='Cache busting: True / False default: True')
        parser.add_argument("-v", "--showdetails", choices=['true', 'false'], default='false', action="store",
                            required=False, help='Getting more information True / False default: False')
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
                r = requests.post(self.url, json={"url": "" + input_value + "", "skipcache": "true"}, timeout=200)
            elif showdetails == "true" and skipcache == "true":
                r = requests.post(self.url, json={"url": "" + input_value + "", "showdetails": "true", "skipcache": "true"}, timeout=200)
            elif showdetails == "true" and skipcache == "false":
                r = requests.post(self.url, json={"url": "" + input_value + "", "showdetails": "true"}, timeout=200)
            else:
                r = requests.post(self.url, json={"url": "" + input_value + ""}, timeout=200)

        except requests.exceptions.Timeout:
            self.httpcode = 308
            message = config.message_timeout + ' url=' + input_value + ' httpcode=' + repr(self.httpcode)
            scan_value = 1
            print message

        except requests.exceptions.TooManyRedirects:
            self.httpcode = 308
            message = config.message_redirects + ' url=' + input_value + ' httpcode=' + repr(self.httpcode)
            scan_value = 1
            print message


        except requests.exceptions.RequestException:
            self.httpcode = 500
            message = config.message_req_exception + ' url=' + input_value + ' httpcode=' + repr(self.httpcode)
            scan_value = 1

            # Thread the process: Restarting Securityapi
            #thread = MySimpleThread((self.cmd), result_queue)
            #thread.start()
            #(cmd, output, status) = result_queue.get()

        if scan_value == 0:
            # Opening the result
            self.httpcode = r.status_code
            try:
                output_scan = simplejson.loads(simplejson.dumps(r.json()))
            except ValueError:
                message = config.message_req_exception
                MyLogger.write_log(message)
                print(message)

            # if Error when retriving the data
            try:
                compliance = output_scan[0]["status"]
            except KeyError:
                error_message = config.message_no_json
                MyLogger.write_log("error=" + error_message + " " + "url=" + input_value)
            except IndexError:
                error_message = config.message_no_json
                MyLogger.write_log("error=" + error_message + " " + "url=" + input_value)

        return self.httpcode, compliance, output_scan

# thread class to run a command
class MySimpleThread(threading.Thread):
    def __init__(self, cmd, queue):
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.queue = queue

    def run(self):
        # execute the command, queue the result
        (status, output) = commands.getstatusoutput(self.cmd)
        self.queue.put((self.cmd, output, status))

# queue where results are placed
result_queue = Queue.Queue()

# thread class to run a command
class myThread(threading.Thread):
    def __init__(self, threadID, name, q):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.q = q

    def run(self):
        #print("Starting " + self.name)
        process_data(self.name, self.q)
        #print("Exiting " + self.name)

def process_data(threadName, q):
    new_urls_list = {}
    while not exitFlag:
        queueLock.acquire()
        if not workQueue.empty():
            data = q.get()
            queueLock.release()

            scan = 0
            for row in data:
                url = row["name"].split(" ")[0]
                source = row["Source"].replace(" ", "_")

                if url in DICO_DOMAIN:
                    if DICO_DOMAIN[url] == 405:
                        scan = 1

                if scan == 0:
                    httpcode, compliance, output_scan = MyURLScanner.scan_entry(url, args.skipcache, args.showdetails)
                    print(httpcode, compliance, url)

                if httpcode:
                    # Create log for domainscanner
                    message = 'url=' + url + ' httpcode=' + repr(httpcode) + " " + "compliance=" + compliance + " " + "source_records=" + source + " " + "source_scan=cmdb"
                    MyLogger.write_scanlog(message)

                    # Update file with all domains
                    new_urls_list[url] = httpcode
                    URL_LIST.update(new_urls_list)

        else:
            queueLock.release()
        time.sleep(1)

nameList = []
threadList = [1,2,3,4,5,6,7,8,9,10]
queueLock = threading.Lock()
workQueue = Queue.Queue(10)
threads = []
threadID = 1


#################################################
#
# START
#
#################################################

if __name__ == '__main__':
    total = 0
    nb_notcompliant = 0
    list = []
    output_scan = {}

    cmdb_httpcode = 200
    cmdb_url = "[URL]"

    MyURLScanner = URLScanner()
    parser = MyURLScanner.createParser()
    args = parser.parse_args()

    # TEST CMDB connexion
    try:
        r = requests.get(cmdb_url + repr(1), timeout=20)
        httpcode = r.status_code
    except:
        message = "message=" + config.message_cmdb_not_reachable
        MyLogger.write_log(message)
        cmdb_httpcode = 500

    # if CMDB is reachable
    if cmdb_httpcode == 200:

        # ADD file entry to dic
        domain_file_tmp = open(config.DOMAIN, 'r')
        for dom in domain_file_tmp:
            dom_url = dom.rstrip().split(":")[0]
            dom_httpcode = dom.rstrip().split(":")[1]

            DICO_DOMAIN[dom_url] = dom_httpcode
        domain_file_tmp.close()

        print(DICO_DOMAIN)

        # Open file domain.txt
        domain_file = open(config.DOMAIN, 'w')

        # create thread for the scan
        for thrd in threadList:
            # Create new threads
            thread = myThread(thrd, "thread" + repr(thrd), workQueue)
            thread.start()
            threads.append(thread)

        # request CMDB URL
        count = 1
        while (count <= 68):

            r = requests.get(cmdb_url+repr(count), timeout=20)

            # Fill the queue with URL
            if r.status_code == 200:
                output_scan[count] = simplejson.loads(simplejson.dumps(r.json()))
                queueLock.acquire()
                workQueue.put(output_scan[count])
                queueLock.release()

            elif r.status_code == 403:
                print(r.json()["detail"])
                message = "message=" + str(r.json()["detail"]) + " " + "httpcode=" + repr(r.status_code) + " " + "pagenumber=" + repr(count)
                MyLogger.write_log(message)

            elif r.status_code == 404:
                message = "message=" + str(
                    r.json()["message"]) + " " + "httpcode=" + repr(r.status_code) + " " + "pagenumber=" + repr(count)
                MyLogger.write_log(message)
            else:
                message = "message=" + config.message_req_exception + " " + "httpcode=" + repr(500) + " " + "pagenumber=" + repr(count)
                MyLogger.write_log(message)

            # increment
            count += 1

    else:
        report_file = MyURLScanner.open_file(config.DOMAIN)

        # Reading the file
        for row in report_file:
            url = row.split(":")[0]
            httpcode, compliance, output_scan = MyURLScanner.scan_entry(url, args.skipcache, args.showdetails)
            print(httpcode, compliance, url)

    # Wait for queue to empty
    while not workQueue.empty():
        pass

    # Notify threads it's time to exit
    exitFlag = 1

    # Wait for all threads to complete
    for t in threads:
        t.join()

    if cmdb_httpcode == 200:
        # update the file domain.txt
        for key, value in URL_LIST.items():
            domain_file.write('%s:%s\n' % (key, value))

        domain_file.close()

    MyLogger.write_log(config.message_success)
    print("###### Scan finished ######")
