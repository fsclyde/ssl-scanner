# -*- coding: utf-8 -*-
#!/usr/bin/env python
#################################################
#
#  Settings
#
#################################################
import logging
import logging.handlers


URL="http://127.0.0.1:8080/api/ssl/v1.0/amicompliant"

DOMAIN="[domain-file-path]"
JOURNAL="/var/log/domainscanner_error.log"
DOMSCANLOGS="/var/log/domainscanner.log"

FORMAT="%(asctime)-15s %(message)s"

# Error Messages
message_no_file  = "The_file_does_not_exist"
message_no_json = "Error_parsing_json"
message_timeout = "Maybe_set_up_for_a_retry"
message_redirects = "To_many_redirect"
message_req_exception = "fatal_error_check_server"
message_success = "Scan_all_FT_Domain_properly_terminated"
message_cmdb_not_reachable = "CMDB_is_not_reachable"

log = logging.getLogger('werkzeug')
log.disabled = True

# Class logging
class Logger(object):
	def write_log(self, logstrings): 
		logging.basicConfig(filename=JOURNAL,format=FORMAT)
		logging.error(logstrings)

	def write_scanlog(self, logstrings):
		logging.basicConfig(filename=DOMSCANLOGS, format=FORMAT)
		logging.error(logstrings)

