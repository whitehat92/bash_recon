#!/bin/bash
if [ ! -d "$1" ]; then
mkdir $1
else
echo "\e[32m Overwriting results for $1 \e[0m"
fi
echo $1 > $1/searchedfor.txt
#if there is a string after the first name separated by a / which we cannot create folders with, then create with 3rd printed string and 4th
echo "\e[32m Analyzing "$1" and generating html report\e[0m"
echo "<html>" > $1/$1.html
echo "<head>" >> $1/$1.html
echo "<link rel='stylesheet' href='https://fonts.googleapis.com/css?family=Mina' rel='stylesheet'>" >> $1/$1.html
echo "</head>">> $1/$1.html
echo "<body><meta charset='utf-8'> <meta name='viewport' content='width=device-width, initial-scale=1'> <link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css'> <script src='https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js'></script> <script src='https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js'></script></body>">> $1/$1.html
echo "<div class='jumbotron text-center'><h1> Recon Report for domain "$1" </h1>" >> $1/$1.html
echo "\e[32m Amass to enumerate $1 \e[0m"
echo "<div class='jumbotron text-center',style='font-family:'Mina', serif'><h2>Amass Details on $1</h2></div>" >> $1/$1.html
echo "<pre style='display: block;'class='jumbotron text-left'>" >> $1/$1.html
#ping -c 1 $1 > $1/$1_ping.txt
#sh ~/tools/SCRIPTS/grep_ping.sh $1/$1_ping.txt > $1/$1_ip.txt
#curl http://ipinfo.io/$(cat ~/tools/$1/$1_ip.txt) >> $1/$1.html
amass enum -d https://$1 >> $1/$1.html
amass enum --passive -d $1 -json $1.json jq .name $1.json | sed "s/\"//g"| httprobe -c 60 | tee -a $1/$1_subdomainsfromamass.txt
cat ~/tools/$1/$1_subdomainsfromamass.txt >> ~/tools/$1/$1.html
echo "\e[32m generating subdomains list for Burp \e[0m"
cd ~/tools/$1
sh ~/tools/SCRIPTS/burpdirs.sh $1
cd ..
echo "</pre>" >> $1/$1.html
echo "\e[32m Analyzing ip of the target.. \e[0m"
echo "<div class='jumbotron text-center',style='font-family:'Mina', serif'><h2>IP analyzis</h2></div>" >> $1/$1.html
echo "<pre style='display: block;'class='jumbotron text-left'>" >> $1/$1.html
ping -c 1 $1 > $1/$1_ping.txt
sh ~/tools/SCRIPTS/grep_ping.sh $1/$1_ping.txt > $1/$1_ip.txt
curl http://ipinfo.io/$(cat ~/tools/$1/$1_ip.txt) >> $1/$1.html
echo "</pre>" >> $1/$1.html
echo "\e[32m Whoising the target.. \e[0m"
echo "<div class='jumbotron text-center',style='font-family:'Mina', serif'><h2>WHOIS</h2></div>" >> $1/$1.html
echo "<pre style='display: block;'class='jumbotron text-left'>" >> $1/$1.html
whois $1 >> $1/$1.html;
echo "</pre>" >> $1/$1.html
echo "<div class='jumbotron text-center',style='font-family:'Mina', serif'><h2>Dig Info</h2></div>" >> $1/$1.html
echo "<pre style='display: block;'class='jumbotron text-left'>" >> $1/$1.html
dig $1 >> $1/$1.html;
echo "</pre>" >> $1/$1.html
echo "<div class='jumbotron text-center',style='font-family:'Mina', serif'><h2>Host Info</h2></div>" >> $1/$1.html
echo "<pre style='display: block;'class='jumbotron text-left'>" >> $1/$1.html
host $1 >> $1/$1.html;
echo "</pre>" >> $1/$1.html
echo "<div style='font-family: 'Mina', serif;'><h2>Response Header</h2></div>" >> $1/$1.html
echo "<pre>" >> $1/$1.html
curl -I -X GET $1 >> $1/$1.html;
echo "</pre>" >> $1/$1.html
echo "<div style='font-family: 'Mina', serif;'><h2>NIKTO</h2></div>" >> $1/$1.html
echo "\e[32m Running Nikto for "$1"\e[0m"
echo "<pre>" >> $1/$1.html
cd .. && nikto -h $1 >> ~/tools/$1/$1.html
cd ~/tools && echo "</pre>" >> $1/$1.html
 echo "<div style='font-family: 'Mina', serif;'><h2>NIKTO on HTTPS port</h2></div>" >> $1/$1.html
 echo "\e[32m Running Nikto on https port "$1"\e[0m"
echo "<pre>" >> $1/$1.html
 cd .. && nikto -h $1:443 >> ~/tools/$1/$1.html
 cd ~/tools && echo "</pre>" >> $1/$1.html
echo "<div style='font-family: 'Mina', serif;'><h2>TECHNOLOGIES BEHIND IT (WHATWEB)</h2></div>" >> $1/$1.html
echo "<pre>" >> $1/$1.html
#cd .. && whatweb $1 >> ~/tools/$1/$1.html 
echo "\e[32m Analyzing technologies and putting them in a txt file. Wait a sec.. \e[0m"
#cd ~/tools && whatweb $1 >> $1/$1.tech.txt
cd .. && whatweb $1 > ~/tools/$1/$1.tech.txt
echo "\e[32m Putting tech without any code in the html.. \e[0m"
bash ~/tools/SCRIPTS/greptech.sh ~/tools/$1/$1.tech.txt >> ~/tools/$1/$1.html
cd ~/tools/
echo "</pre>" >> $1/$1.html
echo "<div style='font-family: 'Mina', serif;'><h2>SUBDOMAINS FOUND</h2></div>" >> $1/$1.html
echo "\e[32m Trying to find subdomains for "$1"\e[0m"
echo "<pre>" >> $1/$1.html
echo "<h3> if anything found here, information also  present above with Amass </h4>" >> $1/$1.html
python ~/tools/sublister/sublist3r.py -v -d $1 -t 30 | less -S >> $1/$1.html
~/tools/findomain-linux -t $1 -o txt >> $1/$1.html
#echo "<h4> results with syborg (for more possibilities, edit this script to include a wordlist) </h4>" >> $1/$1.html
#python3 ~/tools/Syborg/syborg.py $1 >> $1/$1.html
echo "<h4> results from assetfinder</h4>" >> $1/$1.html
echo $1 | assetfinder | httprobe > $1/$1_subdomains_alive.txt
echo "\e[32m Appending subdomains found from assetfinder into file \e[0m"
cat ~/tools/$1/$1_subdomains_alive.txt >> ~/tools/$1/$1.html
echo "</pre>" >> $1/$1.html
echo "\e[32m Let me just put what we found from sublister in a txt file, real quick..\e[0m"
sleep 2;
python ~/tools/sublister/sublist3r.py -v -d $1 -t 30 | less -S > $1/$1.subdomains.txt
echo "<div style='font-family: 'Mina', serif;'><h3´>More organized subdomains</h3></div>" >> $1/$1.html
echo "\e[32m Putting subdomains more organized in the html report\e[0m"
echo "<pre>" >> $1/$1.html
bash ~/tools/SCRIPTS/sedsubdomains.sh $1/$1.subdomains.txt >> $1/$1.html
echo "</pre>" >> $1/$1.html
echo "<div style='font-family: 'Mina', serif;'><h3´>WAYBACK URLS</h3></div>" >> $1/$1.html
echo "\e[32m Fetching from wayback some information\e[0m"
echo "<pre>" >> $1/$1.html
echo $1 | waybackurls >> $1/$1.html
echo "</pre>" >> $1/$1.html
#echo "<div style='font-family: 'Mina', serif;'><h2>MAYBE SOME BUCKETS?</h2></div>" >> $1/$1.html
#echo "\e[32m Searching for buckets for $1\e[0m"
#echo "<pre>" >> $1/$1.html
#cd ~/tools/teh_s3_bucketeers/
#bash bucketeer.sh $1 >> ../$1/$1.html
#cd ~/tools
#ruby ~/tools/lazys3/lazys3.rb $1 >> $1/$1.html
#echo "</pre>" >> $1/$1.html
echo "\e[32m Now up to ASNLOOKUP for "$1"\e[0m"
echo "<div style='font-family: 'Mina', serif;'><h2>ASNLOOKUP..</h2></div>" >> $1/$1.html
echo "<pre>" >> $1/$1.html
python3 ~/tools/asnlookup/asnlookup.py -o $1 >> $1/$1.html
echo "</pre>" >> $1/$1.html
echo "<div style='font-family: 'Mina', serif;'><h2>VIRTUAL HOST DISCOVERY</h2></div>" >> $1/$1.html
echo "\e[32m Trying to find some other hosts "$1"\e[0m"
echo "<pre style='display: block;'class='jumbotron text-center'>"  >> $1/$1.html
cd ~/tools/virtual-host-discovery/ && ruby scan.rb --ip=$(host $1) --host=$1 >> ../$1/$1.html
echo "\e[32m Let me also put the virtual host discovery results in a txt file.. "$1"\e[0m"
ruby scan.rb --ip=$(host $1) --host=$1 >> ../$1/$1.virtualhosts.txt
echo "</pre>" >> ../$1/$1.html 
cd ~/tools && echo "<div style='font-family: 'Mina', serif;'><h2>WHAT FOLDERS DO WE HAVE HERE..</h2></div>" >> $1/$1.html
 echo "\e[32m Sleeping just for 5 seconds.. \e[0m"
sleep 5;
echo "\e[32m Searching for folders on "$1" and outputting them into the html report\e[0m"
echo "<pre class='jumbotron text-left'>" >> $1/$1.html
cd ~/tools/dirsearch
#python3 dirsearch.py -u $1 -e html,htm,js,php,conf,dist,cnf,info,sql,asp,net,aspnet,dst,mysql,doc,pdf,xls,info,inf,txt,odt,php3,php4,php5,phtml,lib,test,inc,index,war,foo,rdz,zip,7z -t 50 >> ~/tools/$1/$1.html
#echo \e[32m I've finished reporting the folders we have for the domain, but now let me put what I found in a separate txt file \e[0m"
#sleep 3;
python3 dirsearch.py -u $1 -e html,htm,js,php,conf,dist,cnf,info,sql,asp,net,aspnet,dst,mysql,doc,pdf,xls,info,inf,txt,odt,php3,php4,php5,phtml,lib,test,inc,index,war,foo,rdz,zip,7z,.html,.htm,.js,.php,.conf,.dist,.cnf,.info,.sql,.asp,.net,.aspnet,.dst,.mysql,.doc,.pdf,.xls,.info,.inf,.txt,.odt,.php3,.php4,.php5,.phtml,.lib,.test,.inc,.index,.war,.foo,.rdz,.zip,.7z -r -t 100 -x 301,329 >> ~/tools/$1/$1.folders.txt
 echo "<div style='font-family: 'Mina', serif;'><h3>More organized folders</h3></div>" >> ~/tools/$1/$1.html
 echo "\e[32m Adding the folders in a more organized way into the html report \e[0m"
echo "<pre style='display: block;'class='jumbotron text-left'>"  >> ~/tools/$1/$1.html
 sh ~/tools/SCRIPTS/sedrequestcodes_nocode.sh ~/tools/$1/$1.folders.txt | sort -u >> ~/tools/$1/$1.html
 echo "\e[32m Taking care of 403 code in the html \e[0m"
cd ~/tools/$1
sh ~/tools/SCRIPTS/403code.sh $1.folders.txt | sort -u  >> $1.html
 echo "\e[32m Now it's 200's turn. Wait a sec.. \e[0m"
sh ~/tools/SCRIPTS/200code_new.sh $1.folders.txt | sort -u  >> $1.html
echo "\e[32m Now going to 500 code.. \e[0m"
sh ~/tools/SCRIPTS/500code.sh $1.folders.txt | sort -u >> $1.html
 echo "\e[32m Now going to 400 code. Won't take that long.. \e[0m"
sh ~/tools/SCRIPTS/400code.sh $1.folders.txt | sort -u >> $1.html
cd ~/tools
 echo "</pre>" >> ~/tools/$1/$1.html
cd ~/tools
echo "</pre>" >> $1/$1.html
echo "</div>" >> $1/$1.html
cd ~/tools && echo "<div style='font-family: 'Mina', serif;'><h2>JS FILES..</h2></div>" >> $1/$1.html
echo "\e[32m Getting js files from "$1". Saved as $1_output\e[0m"
echo "<pre>" >> $1/$1.html
#wget -U "Mozilla/5.0" --recursive --domains --no-parent --page-requisites --html-extension --convert-links --no-clobber  $1 >> $1/$1.html
gjs https://$1 >> $1/$1-html
getjs https://$1 >> $1/$1.html
echo "</pre>" >> $1/$1.html
cd ~/tools && echo "<div style='font-family: 'Mina', serif;'><h2>From the index page..</h2></div>" >> $1/$1.html
echo "\e[32m Analyzing index page briefly looking for comments, js reference, hidden fields and forms\e[0m"
#echo "<pre>" >> $1/$1.html
wget --no-check-certificate $1 > $1/$1.index.html
wget --no-check-certificate https://$1 > $1/$1.index.html
#echo "<h5>Checking out with https..<h5/>" $1 >> $1/$1.html
#cd ..
#wget -r --no-check-certificate $1 >> ~/tools/$1/$1.html
#cd ~/tools
#echo "</pre>" >> $1/$1.html else ; fi
echo "<div style='font-family: 'Mina', serif;'><h3>FORMS</h3></div>" >> $1/$1.html
echo "<pre>" >> $1/$1.html
cd ..
grep -EHr "input" ~/tools/$1/$1.index.html >> ~/tools/$1/$1.html
grep -EHr "input" ~/tools/$1/$1.index.html >> ~/tools/$1/$1.html
grep -EHr "<form action"  ~/tools/$1/$1.index.html >> ~/tools/$1/$1.html
grep -EHr "input type="  ~/tools/$1/$1.index.html >> ~/tools/$1/$1.html
echo "</pre>" >> ~/tools/$1/$1.html
cd ~/tools && echo "<div style='font-family: 'Mina', serif;'><h3>HIDDEN FIELDS</h3></div>" >> $1/$1.html
echo "<pre>"  >> $1/$1.html
cd ..
grep -EHr "type=hidden" ~/tools/$1/$1.index.html  >>  ~/tools/$1/$1.html
grep -EHr "type=hidden " ~/tools/$1/$1.index.html  >>  ~/tools/$1/$1.html
echo "</pre>"  >> ~/tools/$1/$1.html
cd ~/tools && echo "<div style='font-family: 'Mina', serif;'><h3>LINKS</h3></div>" >> $1/$1.html
echo "<pre>"  >> $1/$1.html
grep -EHr 'href="[^\"]+"' $1/$1.index.html >>  ~/tools/$1/$1.html
grep -EHr '(http|https)://[^/"]+' $1/$1.index.html >>  ~/tools/$1/$1.html
echo "</pre>"  >> $1/$1.html
cd ~/tools && echo "<div style='font-family: 'Mina', serif;'><h3>COMMENTS</h3></div>" >> $1/$1.html
echo "<pre>"  >> $1/$1.html
grep -EHr "<!-- "  ~/tools/$1/$1.index.html  >>  ~/tools/$1/$1.html
grep -rHE "<!-- " ~/tools/$1/$1.index.html  >>  ~/tools/$1/$1.html
grep -EHr "<! " ~/tools/$1/$1.index.html  >>  ~/tools/$1/$1.html
grep -EHr "<!" ~/tools/$1/$1.index.html  >>  ~/tools/$1/$1.html
echo "</pre>"  >> $1/$1.html
echo "\e[32m Using certspotter for the domain "$1"\e[0m"
echo "<div style='font-family: 'Mina', serif';class='jumbotron text-center'><h2>CERTSPOTTER</h2></div>"  >> $1/$1.html
echo "<pre>" >> $1/$1.html
curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1 >> $1/$1.html
echo "</pre>" >> $1/$1.html
echo "<div style='font-family: 'Mina', serif';class='jumbotron text-left'><h2>CRTSH WHAT DOMAINS DO WE HAVE FROM THE CERTIFICATES</h2></div>"  >> $1/$1.html
echo "<pre>" >> $1/$1.html
curl -s https://crt.sh/?q=%.$1  | sed 's/<\/\?[^>]\+>//g' | grep $1 >> $1/$1.html
echo "</pre>" >> $1/$1.html
echo "\e[32m Running tests against the firewall for the domain "$1"\e[0m"
echo "<div style='font-family: 'Mina', serif;'><h2>IS IT BEHIND A WAF or any kind of firewall?</h2></div>" >> $1/$1.html
echo "<pre>" >> $1/$1.html
wafw00f -a $1 >> $1/$1.html
sh ~/tools/firewallbypass/firewallbypass.sh -d $1 -a >> $1/$1.html
python3 ~/tools/WhatWaf/whatwaf.py -u $1 >> $1/$1.html
echo "</pre>" >> $1/$1.html
echo "\e[32m Nmapping the domain.. "$1"\e[0m"
echo "<div style='font-family: 'Mina', serif;'><h2>Fast Check with Nmap</h2></div>" >> $1/$1.html
echo "<pre style='display: block;'>" >> $1/$1.html
echo "\e[32m Running now nmap for "$1"\e[0m"
nmap -v $1 >> $1/$1.html
echo "</pre>" >> $1/$1.html
echo "<div style='font-family: 'Mina', serif;'><h1>General Services</h1></div>" >> $1/$1.html
echo "<pre style='display: block;'>" >> $1/$1.html
nmap -v -sC $(cat ~/tools/$1/$1_ip.txt) >> $1/$1.html
echo "</pre>" >> $1/$1.html
#echo "\e[32m agressively nmapping the top 100 ports against target "$1"\e[0m"  >> $1/$1.html
#echo "<div style='font-family: 'Mina', serif;'><h1>NMAP AGRESSIVE TOP 100 PORTS</h1></div>" >> $1/$1.html
#echo "<pre style='display: block;'>" >> $1/$1.html
#nmap -v -sSV -A -O -T2 -Pn --top-ports 100 $(cat ~/tools/$1/$1_ip.txt) >> $1/$1.html
#echo "</pre>" >> $1/$1.html
#echo "\e[32m Vulnerability checking with nmap "$1"\e[0m"  >> $1/$1.html
#echo "<div style='font-family: 'Mina', serif;'><h1>Vulnerability check</h1></div>" >> $1/$1.html
#echo "<pre style='display: block;'>" >> $1/$1.html
#nmap -vvv -T2 --script vuln $(cat ~/tools/$1/$1_ip.txt) >> $1/$1.html
#echo "</pre>" >> $1/$1.html
#echo "\e[32m Running aquatone on "$1"\e[0m"  >> $1/$1.html
#echo "<div style='font-family: 'Mina', serif;'><h1>Ports for the common web services</h1></div" >> $1/$1.html
cd $1
echo "<pre style='display: block;'>" >> $1.html
cat searchedfor.txt | aquatone-discover -d  $1 >> $1.html
echo "<h5>aquatone checking ports</h5>" >> $1.html
cat searchedfor.txt | ports >> $1.html
cat aquatone_urls.txt >> $1.html
echo "<h5>hosts present in the .txt file</h5>" >> $1.html
cat ~/aquatone/$1/hosts.txt >> $1.html
cd ..
echo "</pre>" >> $1/$1.html
echo "</body>" >> $1/$1.html
echo "</html>" >> $1/$1.html
echo "\e[32m Finalizing report for "$1"\e[0m"
echo "\e[32m Please run now some subdomain takeover tool to find out more things \e[0m"
fi
