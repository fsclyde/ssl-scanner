# ssl-Scanner
SSL / TLS domain list vulnerability Scanner.
This module is a simple URL scanner which will use the SSL scanner to scan a specific list of domain URL and disclose the top of most vulnerable domain.

**This module requiered to use the module SSL Scanner**


### USAGE

Please use python python27

First start with the SSL / TLS Scanner.

```
pip install flask_restful_swagger flask_restful flask
python server/app.py
```

The SSL Scanner will listen on: http://127.0.0.1:8080

Then, you can carry on with alldomainscanner, which contain the script which will scan the whole list of domain name and shows the results.

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

alldomainscanner will perform the scan of the list of URL present within the file **DOMAIN="[file]"** by using the endpoint [amicompliant](http://127.0.0.1:8080/api/ssl/v1.0/amicompliant) 

Go on **http://127.0.0.1:8081/reports**

### Some interesting links about SSL / TLS

* [SSL/TLS History](https://www.feistyduck.com/ssl-tls-and-pki-history/)
* [TLS Understanding](https://en.wikipedia.org/wiki/Transport_Layer_Security)
* [SSL/TLS Pentesting](http://www.exploresecurity.com/wp-content/uploads/custom/SSL_manual_cheatsheet.html)

