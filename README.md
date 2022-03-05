# RustScan
Scans for indications of an XSS vuln, Oracle SQLi and filters out words containing MySQL. Best used along side ParamSpider found at
https://github.com/devanshbatham/ParamSpider

```
python3 ./paramspider.py -d WEBSITE.com -p Bugbounty --exclude js,jpg,png,css,woff,ttf,svg,ashx,gif,svg,pdf --subs false -o ./hosts.txt
```
and then run the RustScan in the same directory as hosts.txt


<h1>To compile</h1>
```

git clone https://github.com/frostb1ten/RustScan.git
cd RustScan
cargo build

```
<h2>Compiled version at https://github.com/frostb1ten/RustScan/raw/main/RustScan.7z</h2>


<h3>***This tool is for VDP/Bugbounty useage only. We are not liable for any damages or trouble caused by this scanner.***</h3>
