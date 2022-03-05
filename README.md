# RustScan
Scans for indications of an XSS vuln, Oracle SQLi and filters out words containing MySQL. Best used along side ParamSpider found at
https://github.com/devanshbatham/ParamSpider

```
python3 ./bin/ParamSpider/paramspider.py -d WEBSITE.com -p Bugbounty --exclude js,jpg,png,css,woff,ttf,svg,ashx,gif,svg,pdf --subs false -o ./hosts.txt
```
and then run the RustScan in the same directory as hosts.txt



<h3>***This tool is for VDP/Bugbounty useage only. We are not liable for any damages or trouble caused by this scanner.***</h3>
