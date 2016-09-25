# SSL-Scanner
SSL domain list vulnerability Scanner.
This module is a simple URL scanner which will use the SSL scanner to scan a specify list of domains and disclose the top of vulnerable domain.

**This module requiered to use the module SSL Scanner**


### USAGE

Please use python python27

First start with the SSL Scanner

```
pip install flask_restful_swagger flask_restful flask
python server/app.py
```

The SSL Scanner will listen on: http://127.0.0.1:8080

Then you can carry on with Alldomainscanner, which will scan 

```
pip install requests simplejson coffeescript
cd alldomainscanner/
python main.py
```


Edit the file **config.py** and add the absolute file path of the domain file that you want to use.

```
vim alldomainscanner/config.py

DOMAIN="[domain-file-path]"

```

Then use **scanner.py** to scanner your URL 
 
```
python scanner.py -s true/false
```

true: skipcache when it scans URL
false: use last cached scan informations

alldomainscanner will perform the scan of the list of URL present within the file DOMAIN="[file]" by using the endpoint **http://127.0.0.1:8080/api/ssl/v1.0/amicompliant**

Go on **http://127.0.0.1:8081/reports**