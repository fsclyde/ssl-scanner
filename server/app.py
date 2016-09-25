# -*- coding: utf-8 -*-
#!/usr/bin/python
#!flask/bin/python
'''
Running:

'''
# Flask modulesgo
from flask import Flask, jsonify
from sslcheck import sslcheck
from sslcheck import sslscanner

from models import VulnModel, ArachniModel
from flask import Blueprint
from flask_restful import Resource, Api
from flask_restful_swagger import swagger
from datetime import datetime
import requests, config, simplejson
from config import *


app = Flask(__name__)

healthcheck = Blueprint('healthcheck', __name__)
healthcheck_resource = swagger.docs(Api(healthcheck))


#################################################
#
# START
#
#################################################

URL = "scan.in.ft.com"

def get_response(input_request, withoutparam):
    httpcode = 200

    try:
        if withoutparam == False:
            data = {"url": "scan.in.ft.com"}
            r = requests.post("http://127.0.0.1:8080/api/ssl/v1.0/amicompliant", data=simplejson.dumps(data), headers={'Content-Type': 'application/json'},timeout=200)
        else:
            r = requests.get(input_request)

        httpcode = r.status_code
    except requests.exceptions.Timeout:
        message = config.message_timeout
        scan_value = 1
        httpcode = r.status_code

    except requests.exceptions.TooManyRedirects:
        message = config.message_redirects
        scan_value = 1
        httpcode = r.status_code

    except requests.exceptions.RequestException:
        message = config.message_req_exception
        scan_value = 1
        httpcode = r.status_code
        Logger.write_log(message)

    if httpcode in [200,403]:
        response = True
    else:
        response = False

    return response, httpcode


@app.route("/spec")
def spec():
    return jsonify(swagger(app))


# HealthCheck
class HealthCheck(Resource):
    def get(self):

        scan_endpoint_resp, scan_code = get_response("https://scan.in.ft.com:443/api/ssl/v1.0/scan",withoutparam = False )
        compliant_endpoint_resp, compliant_code  = get_response("https://scan.in.ft.com:443/api/ssl/v1.0/amicompliant", withoutparam = False)
        ssl_dashboard_resp, ssl_dashboard_code = get_response("https://scan.in.ft.com/api/ssl/v1.0/details/scan.in.ft.com", withoutparam = True)

        status = {
                    'schemaVersion': u'1',
                    'systemCode': u'ft-securityapi',
                    'name': u'SSLscanner',
                    'description': u'SSL scanner components: scan, compliance checking, getmetrics',
                    'checks': [
                    {
                        'id': u'1',
                        'name': u'SCAN Vulnerabilites SSL Scan Endpoint',
                        'ok': scan_endpoint_resp,
                        'severity': 2,
                        'businessImpact': u'None',
                        'technicalSummary': u'Scan FT URL and display the vulnerability',
                        'panicGuide': u'http://git.svc.ft.com/projects/SEC/repos/ft-securityapi/browse/runbook/securityapi.md',
                        'checkOutput': u'splunk or nagios'

                    },
                    {
                        'id': u'2',
                        'name': u'Amicompliant SSL Scan Endpoint',
                        'ok': compliant_endpoint_resp,
                        'severity': 2,
                        'businessImpact': u'None',
                        'technicalSummary': u'Scan FT URL and display the compliance. https://sites.google.com/a/ft.com/security/securityapi/sslscan',
                        'panicGuide': u'http://git.svc.ft.com/projects/SEC/repos/ft-securityapi/browse/runbook/securityapi.md',
                        'checkOutput': u'splunk or nagios'

                    },
                    {
                        'id': u'3',
                        'name': u'SSL Dashboard Services',
                        'ok': ssl_dashboard_resp,
                        'severity': 2,
                        'businessImpact': u'None',
                        'technicalSummary': u'Scan a the whole FT URL and display the compliance. https://sites.google.com/a/ft.com/security/securityapi/sslscan',
                        'panicGuide': u'http://git.svc.ft.com/projects/SEC/repos/ft-domainscanner/browse/runbook/ftdomainscanner.md',
                        'checkOutput': u'splunk or nagios'

                    }
                ]
            }


        return status, 200, {'Content-Type': 'application/json', 'Cache-control': 'no-store'}


healthcheck_resource.add_resource(HealthCheck,'/__health')


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', "GET, POST")
    response.headers.add('Cache-Control', 'max-age=86400')

    return response


if __name__ == '__main__':

    app.config['BUNDLE_ERRORS'] = True
    app.register_blueprint(healthcheck)
    app.register_blueprint(sslscanner.sslapi, url_prefix='/api')
    app.run(threaded=True, host='127.0.0.1', port=8080)