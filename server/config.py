# -*- coding: utf-8 -*-
#!/usr/bin/env python
#################################################
#
#  Settings
#
#################################################
import logging
import logging.handlers, datetime
from datetime import datetime


#app.config['ABSDIR'] =  os.path.dirname(os.path.abspath(__file__))

URL="http://127.0.0.1:8080/api/ssl/v1.0/amicompliant"
DOMAIN="/opt/ftdomainscanner/domain.txt"
JOURNAL_SSL ="/var/log/apps/sslscan.log" # log file
FORMAT_SCAN = datetime.now().isoformat() +"00:00 %(name)s - INFO - %(message)s" # log file format
FORMAT = datetime.now().isoformat() +"00:00 %(name)s - %(levelname)s - %(message)s" # log file format
JOURNAL_APP="/var/log/apps/securityapi.log" # log file


# Error Messages
message_no_file  = "The file does not exist"
message_timeout = "Maybe set up for a retry, or continue in a retry loop"
message_redirects = "To many redirect"
message_req_exception = "fatal error, check server"

log = logging.getLogger('werkzeug')
log.disabled = True


# Class logging
class Logger(object):
	# Logging apps informations
	def write_log(self, logstrings, logfile):
		logging.basicConfig(filename=logfile,format=FORMAT)
		logging.error(logstrings)
	# Logging scan informations
	def write_log_scan(self, logstrings, logfile):
		logging.basicConfig(filename=logfile, format=FORMAT_SCAN)
		logging.log(logging.ERROR, logstrings)



