# RustScan
Scans for indications of an XSS, Oracle SQLi and filters out words containing MySQL. Best used along side ParamSpider found at
https://github.com/devanshbatham/ParamSpider

```
python3 ./bin/ParamSpider/paramspider.py -d WEBSITE.com -p Bugbounty --exclude js,jpg,png,css,woff,ttf,svg,ashx,gif,svg,pdf --subs false -o ./hosts.txt
```
and then run the RustScan in the same directory as hosts.txt
