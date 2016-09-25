# -*- coding: utf-8 -*-
__author__ = 'clydefondop'
import subprocess
import re, os
import socket
import datetime
from subprocess import Popen, PIPE, CalledProcessError#, TimeoutExpired
import sqlite3
from settings import *
import config

import threading
import Queue
import commands
import time

# thread class to run a command
class MyThread(threading.Thread):
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

MyLogger = config.Logger()


class SSLcheck():
    def __init__(self):
        self.config_class = ConfigClass()
        self.configure_database() # create the sqlite DB if it doesn't exist
        self.ssl_scan_cmd = '/opt/websecapi/server/./testssl.sh -q --color=0 --jsonfile=%(report)s.json --vulnerable --warnings=batch --pfs --rc4 %(url)s'
        self.preflightRequest = True
        self.preflightTimeout = 10
        self.return_http_code = 0
        self.return_report_file = ""
        self.return_message = ""
        self.scan_id = ""  # scan_id
        self.result_base = "" # Result file

    def configure_database(self):
        try:
            self.db_query("Select count(*) from ssl_scans", [])
        except sqlite3.OperationalError:
            ssl_schema = """
            CREATE TABLE ssl_scans
            (
                    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                    scan_id varchar(36) UNIQUE NOT NULL,
                    scan_url text,
                    report_base text,
                    requestor varchar(255),
                    created_at datetime,
                    expired boolean DEFAULT 0,
                    compliance varchar(255) DEFAULT uncheck,
                    no_violation int DEFAULT 0
                    )
            """
            self.db_query(ssl_schema, [])

    #TODO this should be a central function used by all modules...
    def db_query(self, query, queryparams=[]):
        db = sqlite3.connect(self.config_class.db)
        db.text_factory = str
        cursor = db.cursor()
        #db.close()
        output = cursor.execute(query, queryparams)
        db.commit()
        return output

    def save_scan(self, scan):
        # this scan is not what it looks like...
        # the following will not work
        # TODO fix...
        scan_id = scan['scan_id']
        scan_url = scan['scan_url']
        report_base = scan['report_base']
        requestor = scan['requestor']

        querystring = "INSERT INTO ssl_scans (scan_id, scan_url,report_base, requestor, created_at) VALUES (?,?,?,?,datetime('now'))"
        queryparams = [ scan_id, scan_url, report_base, requestor ]

        #TODO log this
        exception = 0
        try:
            cursor = self.db_query(querystring, queryparams)
            queryResult = cursor.fetchall()
        except sqlite3.IntegrityError:
            message = "error when saving the scan"
            print message
            MyLogger.write_log(message, config.JOURNAL_APP)
            # we'll ignore the error for now
            exception = 1
        #return result, exception

    def get_cached_scan(self, scan_target):
        exception = 0
        # how will we expire the results?
        # we also need a cache bypass
        querystr = "SELECT scan_id, scan_url, report_base, requestor, created_at, expired FROM ssl_scans WHERE scan_url = ? AND expired = 0"


        try:
            cursor = self.db_query(querystr, [scan_target])
            queryResult = cursor.fetchall()
            result = None
            for row in queryResult:
                result = {"scan_id" : row[0],
                          "scan_url" : row[1],
                           "report_base" : row[2],
                           "requestor" : row[3],
                           "created_at" : row[4],
                           "expired" : row[5]
                        }
                self.scan_id = row[0] # Get scan id
                #self.result_base = row[2] # Get result file in base

        except sqlite3.IntegrityError:
            self.raise_error("Something went wrong. Please check and try again")
            result = None
            exception = 1
        return result, exception

    def raise_error(self, message=""):
            self.return_http_code = 400
            if len(message) == 0:
                self.return_message = message
            else:
                self.return_message = "An error has occurred."
            message = 'Invalid Input'
            MyLogger.write_log(message, config.JOURNAL_APP)


    def scan(self, parameters):
        scan_target = parameters['url'].lower()

        # It has to be improved
        try:
           skip_cache = parameters['skipcache'].lower()
        except KeyError:
           pass
        try:
           description = parameters['description']
        except KeyError:
           pass
        ###########################
        scan_complete = False

        # let's cache results. but for how long? maybe we can allow a cache purge option
        if skip_cache == "true":
            scanfield = None
        else:
            scanfield, exception = self.get_cached_scan(scan_target)


        if scanfield:
            self.return_report_file = scanfield['report_base']
            # so we do the scan.. this isn't an error
            scan_complete = True
        else:
            """
            logDir = "log"
            checkCmd = "testssl.sh/testssl.sh"
            checkArgs = ["-q", "--color=0 ", "--logfile=" + report_dest+".log", "--jsonfile=" + report_dest+".json", "--csvfile=" + report_dest+".csv", "--vulnerable", "--warnings=batch", "--pfs", "--rc4" ]
            checkTimeout = 90
            rendererCmd = "aha"
            rendererArgs = ["-n"]
            rendererTimeout = 10
            starttls = False
            protocols = ["ftp", "smtp", "pop3", "imap", "xmpp", "telnet", "ldap"]
            protocol = ""
            reHost = re.compile("^[a-z0-9_][a-z0-9_\-]+(\.[a-z0-9_\-]+)*$")
            """
            port = 443 # just ssl for now...
            # Perform preflight request to prevent testssl.sh running into a long timeout
            if self.preflightRequest:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.preflightTimeout)
                    s.connect((scan_target, port))
                    s.close()
                except:
                    message = 'Invalid Input' + ' httpcode=405' + ' url=' + scan_target
                    MyLogger.write_log(message, config.JOURNAL_APP)
                    return 0

            report_url = scan_target.replace("http://", "").replace("https://", "")
            report_suffix = datetime.datetime.now().strftime("%y%m%d_%H%M%S")
            # TODO : base reports directory should be configurable
            report_base = "/opt/websecapi/server/reports/"+"_".join([report_url, report_suffix])

            # let's use a DB to track what we've already scanned, and just return that document instead of doing a scan every time
            cmd = str(self.ssl_scan_cmd % dict(
                report=report_base,
                url=scan_target
            )).split()
            #proc = subprocess.call(cmd, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Thread the process
            thread = MyThread(' '.join(map(str, cmd)), result_queue)
            thread.start()
            (cmd, output, status) = result_queue.get()

            # how do we know which file to return...?
            proc = status

            if proc == 0:
                os.chmod(report_base + ".json", 0775)
                self.scan_id = get_uuid()
                scan_url = scan_target
                report_base = report_base
                requestor = "" # not logged yet - request.remote_addr
                #right now we don't care if this save fails
                scan = {"scan_id" : self.scan_id, "scan_url" : scan_url, "report_base": report_base, "requestor": requestor }
                self.save_scan(scan)
                self.return_report_file = report_base
                self.return_http_code = 200
            else:
                self.return_http_code = 403
        returnset = [ self.return_http_code, self.return_report_file, self.return_message]
        return returnset

    # set compliance value for the scan
    def update_compliance(self, compliance, nb_violation, url):
        querystring = "UPDATE ssl_scans set compliance = ?, no_violation = ? WHERE scan_url = ?"
        queryparams = [ compliance, nb_violation, url ]

        cursor = self.db_query(querystring, queryparams)

    # Get list of not compliant scan
    def get_not_compliant(self):
        querystring = "SELECT DISTINCT(scan_url), no_violation FROM ssl_scans WHERE compliance = 'not compliant' UNION ALL select scan_url, no_violation FROM ssl_scans WHERE compliance = 'not compliant'"
        cursor = self.db_query(querystring)
        queryResult = cursor.fetchall()

        return queryResult

    # Get last scanned scan
    def get_last_scanned(self):
        querystring = "select scan_url,compliance,report_base from ssl_scans order by created_at desc limit 1"
        cursor = self.db_query(querystring)
        queryResult = cursor.fetchall()

        return queryResult

    # Get number of not compliant and compliant
    def get_total_scanned(self):
        querystring = "select 'compliant', count(DISTINCT scan_url) from ssl_scans where compliance='compliant' UNION ALL select 'noncompliant', count(DISTINCT scan_url) from ssl_scans where compliance='not compliant' UNION ALL select 'nb_scanned', count(DISTINCT scan_url) from ssl_scans where compliance != 'uncheck';"
        cursor = self.db_query(querystring)
        queryResult = cursor.fetchall()

        return queryResult
