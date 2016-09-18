# SSL-Scanner
SSL domain list vulnerability Scanner.
This module is a simple URL scanner which will use the SSL scanner to scan a specify list of domains and disclose the top of vulnerable domain.

**This module requiered to use the module SSL Scanner**

### USAGE

Please use python python27

```
pip install requests simplejson coffeescript
python alldomainscanner/main.py
```

Go on **http://127.0.0.1:8081/reports**

Then use **scanner.py** to scanner your URL
 
 
```
python scanner.py -s true/false
```

true: skipcache when it scans URL
false: use last cached scan informations