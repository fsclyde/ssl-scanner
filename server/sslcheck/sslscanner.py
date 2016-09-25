# -*- coding: utf-8 -*-
#################################################
#
#  SSL VUNERABILITY SCANNER
#
#################################################
import datetime, json, simplejson, os
from flask import jsonify, request, abort, make_response, redirect, Blueprint, Response
from flask_restful import reqparse, abort, Api, Resource, fields
from flask_restful_swagger import swagger
from json import JSONEncoder
from flask.views import MethodView
import re, Queue

from models import SslModel, ComplianceModel
from settings import *
import sslcheck, settings
import config
from collections import *

sslapi = Blueprint('sslapi', __name__)
ssl = sslcheck.SSLcheck()
MyLogger = config.Logger()

###################################
# SSL Scanner
####################################

ssl_resource = swagger.docs(Api(sslapi))
nslookup_cmd = "nslookup %(host)s"

# queue where results are placed
result_queue = Queue.Queue()

# Akamai / ELB Check
def lookup_check(input_host, input_str):

    # Nslookup check if the input string is here
    cmd = str(nslookup_cmd % dict(
        host=input_host)).split()

    # Thread the process
    thread = sslcheck.MyThread(' '.join(map(str, cmd)), result_queue)
    thread.start()
    (cmd, output, status) = result_queue.get()

    var_found = [s for s in input_str if s in output]

    return var_found

# open file
def open_file(input_file):
    report_read = ""
    try:
        # load and return our json file
        fh = open(input_file + ".json", 'r')
        report_read = fh.read()
        fh.close()
    except IOError:
        abort(500, message='No such file directory')
        message = 'No such file directory' + input_file
        MyLogger.write_log(message, config.JOURNAL_APP)

    return report_read


#### SSL prepare scan  #####
def ssl_get_output(args):
    scan_target = args
    scan_output = ssl.scan(scan_target)
    try:
        http_code = scan_output[0]
    except TypeError:
        http_code = 405
        message = 'Invalid Input' + ' url=' + scan_target['url'] + ' httpcode=' + `http_code`
        abort(http_code, message=message)


    report_destination = scan_output[1]
    message = scan_output[2]

    if 400 <= http_code <= 499:
        message = 'Invalid Input' +  ' url=' + scan_target['url'] + '  httpcode=' + `http_code`
        MyLogger.write_log(message, config.JOURNAL_SSL)
        abort(http_code)
    else:
        report_read = open_file(report_destination)
        try:
            report_body = simplejson.loads(report_read)
            http_code = 200
        except ValueError:
            http_code = 500
            abort(500, message='JSon parsing error: try with skipcache: true')
            message = 'JSon parsing error' + scan_target + ' url=' + scan_target['url'] + ' httpcode=' + `http_code`
            MyLogger.write_log(message, config.JOURNAL_SSL)

    return report_body, http_code


def open_report(report_destination):
    report_body = []
    report_read = open_file(report_destination)
    try:
        report_body = simplejson.loads(report_read)
    except ValueError:
        abort(500, message='JSon parsing error: try with skipcache: true')
        message = 'JSon parsing error' + report_destination
        MyLogger.write_log(message, config.JOURNAL_APP)

    return report_body


# SSL scan
class SSLscan(Resource):
    def post(self):

        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument('url', type=str, required=True, help='No URL provided for scanning', location='json')
        parser.add_argument('description', type=str, default="", location='json')
        parser.add_argument('filter', type=str, required=False,
                            help="all = show all output [default], vulnerable = show only vulnerable items",
                            default="all")
        parser.add_argument('skipcache', required=False, default="false", help="Cache busting: True / False")
        args = parser.parse_args()

        report_body, http_code = ssl_get_output(args)
        # if valide scan
        if report_body:
            output_result = ""
            filter_mode = args['filter'].lower()
            # Check filter = vulnerable
            if filter_mode.lower() == "vulnerable":
                # just ERR
                new_output = []
                # report = simplejson.loads(report_body)
                for row in report_body:
                    # logging
                    output_result = output_result + " " + "violation=" + row["finding"].replace(" ", "_")
                    if row["severity"] == "NOT OK":
                        new_output.append(row)
                        report_var = str(new_output)

                        try:
                            report_body = simplejson.loads(report_var.replace("'", '"'))
                        except ValueError:
                            abort(400, message='JSon parsing error: try with filter:all ')
                            message = 'JSon parsing error'
                            MyLogger.write_log(message, config.JOURNAL_APP)
            else:
                for row in report_body:
                    # logging
                    output_result = output_result + " " + "violation=" + row["finding"].replace(" ", "_")

        logstring = "url=" + args['url'].lower() + " " + "httpcode=" + `http_code` + " " + "ipaddress=" + \
                    row["ip"].split("/")[1] + " " + output_result
        MyLogger.write_log_scan(logstring, config.JOURNAL_SSL)

        return report_body


# SSL compliance
class SSLCompliant(Resource):
    def post(self):
        new_output = []
        compliance = ""
        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument('url', type=str, required=True, help='No URL provided for scanning', location='json')

        # Finding and solving vulnerability information: default False
        parser.add_argument('showdetails', required=False, default="false",
                            help='help = "Getting more information True / False', location='json')
        # skipping the cache
        parser.add_argument('skipcache', required=False, default="false")

        args = parser.parse_args()

        report_body, http_code = ssl_get_output(args)
        # if valide scan AD Group name (if applicable)
        if report_body:
            # just ERR
            new_output = []
            resultat = []
            list_host = []
            dico = []
            check_aka = lookup_check(args['url'].lower(), settings.exept_akamai) # check Akamai configuration
            check_elb = lookup_check(args['url'].lower(), settings.exept_elb)   # check ELB configuration

            for row in report_body:
                #svar_found = ""
                #var_found = [s for s in settings.exept_tlsv1 if s in row["finding"]]  # TLS exception

                # Check compliance
                if row["severity"] == "NOT OK" and not settings.except_dos_vuln in row["finding"]:

                    # IP added
                    list_host.append(row["ip"])

                    # Violations
                    resultat.append({'host': row['ip'], 'reason': row['finding']})

                    if compliance == "":
                        new_output.append({'url': args['url'].lower(), 'status': 'not compliant'})

                    # set up compliance
                    compliance = False

                # checking Akamai / ELB configuration for the violation "DoS Threat"
                if settings.except_dos_vuln in row["finding"]:
                    if not check_aka and not check_elb:  # if not Akamai or ELB add violation DoS Threat
                        if compliance == "":
                            new_output.append({'url': args['url'].lower(), 'status': 'not compliant'})

                        # set up compliance
                        compliance = False

                        # IP added
                        list_host.append(row["ip"])

                        # Violations
                        resultat.append({'host': row['ip'], 'reason': row['finding']})


            # removed duplicate
            list_host_sorted = list(set(list_host))

            # print list_host_sorted
            if compliance != False:
                new_output.append({'url': args['url'].lower(), 'status': 'compliant'})

                # logging
                logstring = "url=" + args[
                    'url'].lower() + " " + "httpcode=" + `http_code` + " " + "compliance=compliant"
                MyLogger.write_log_scan(logstring, config.JOURNAL_SSL)

                # update compliance and number of violation
                ssl.update_compliance('compliant', 0, args['url'].lower())
            else:
                test = {}
                nb = 1
                nb_violation = 0
                violation = 0
                result_output = ""
                for elem in list_host_sorted:
                    # dico = {'host': elem}
                    for row_finding in resultat:
                        if row_finding['host'] == elem:
                            test['violation' + `nb`] = row_finding['reason']
                            result_output = result_output + " " + 'violation' + "=" + row_finding['reason'].replace(" ","_")
                            nb = nb + 1
                    violation = len(test)

                    # logging
                    logstring = "url=" + args[
                        'url'].lower() + " " + "httpcode=" + `http_code` + " " + "compliance=not_compliant" + " " + "ipaddress=" + \
                                elem.split("/")[1] + " " + result_output
                    MyLogger.write_log_scan(logstring, config.JOURNAL_SSL)

                    if args['showdetails'].lower() == "true":
                        # display results
                        new_output.append({'host': elem.split("/")[1], 'violations': test})
                    test = {}
                    nb = 1
                    nb_violation = 0

                    result_output = ""
                # Show resultat:
                """"violations
                ":[
                    {“violationX”:"xxxxxxx"},
                    {“violationX”:"yyyyyyyy"},
                    {“violationX”:"zzzzzzzzz"}
                ]"""
                # update compliance and number of violation
                ssl.update_compliance('not compliant', violation, args['url'].lower())

                violation = 0

                # report_var = str(new_output)
                # report_body = simplejson.loads(report_var.replace("'", '"'))

        return new_output


# Get metrics of the ssl scan
class SSLScanMetrics(Resource):
    # Get metrics of the ssl scan
    def get(self):
        new_output = []
        result = []

        report = ""
        query_output_get_last_scanned = ssl.get_last_scanned()
        query_output_get_total_scanned = ssl.get_total_scanned()
        query_output_get_not_compliant = ssl.get_not_compliant()

        result_get_last_scanned = []
        result_get_total_scanned = []
        result_get_not_compliant = []

        # SSL SSLastScanned
        for row_report in query_output_get_last_scanned:
            # Conversion to JSON
            result_get_last_scanned.append({"scan_url": row_report[0],
                                            "compliance": row_report[1]
                                            })
            report = row_report[2]
        # GET total scanned URL
        for row_report in query_output_get_total_scanned:
            # Conversion to JSON
            result_get_total_scanned.append({"compliance": row_report[0],
                                             "nb_scanned": row_report[1]
                                             })
        # Getting not compliant URL
        for row_report in query_output_get_not_compliant:
            # Conversion to JSON
            result_get_not_compliant.append({"scan_url": row_report[0],
                                             "no_violation": row_report[1]
                                             })
        if report != "":
            report_body = open_report(report)
            if report_body:
                test = {}
                nb = 1
                list_host = []
                resultat = []
                dico_host = []

                for row in report_body:
                    #var_found = ""
                    #var_found = [s for s in settings.exept_tlsv1 if s in row["finding"]]  # TLS exception

                    # Check compliance
                    if row["severity"] == "NOT OK":
                        list_host.append(row["ip"])
                        resultat.append({'host': row['ip'], 'reason': row['finding']})

                # removed duplicate
                list_host_sorted = list(set(list_host))

                for elem in list_host_sorted:
                    for row_finding in resultat:
                        if row_finding['host'] == elem:
                            test['violation' + `nb`] = row_finding['reason']
                            nb = nb + 1
                    dico_host.append({"host": elem.split("/")[1], "violations": test})
                    nb = 1
                result_get_last_scanned.append(dico_host)

        result = {"lastscanned": result_get_last_scanned, "totalscanned": result_get_total_scanned,
                  "getnotcompliant": result_get_not_compliant}

        return result


class Getdetails(Resource):
    def get(self, urlvalue, username=None):
        dico = {}
        dico["url"] = urlvalue
        dico["skipcache"] = "false"
        dico["filter"] = "all"

        report_body, http_code = ssl_get_output(dico)

        return report_body


ssl_resource.add_resource(SSLscan, '/ssl/v1.0/scan')
ssl_resource.add_resource(SSLCompliant, '/ssl/v1.0/amicompliant')
ssl_resource.add_resource(SSLScanMetrics, '/ssl/v1.0/getmetrics')
ssl_resource.add_resource(Getdetails, '/ssl/v1.0/details/<urlvalue>')

