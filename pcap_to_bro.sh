# Example script to iterate over pcap files to get corresponding http.log and httpheader.log files
for file in ../*.pcap
do
	name=${file##*/}
	echo $name
    base=${name%.pcap}
	echo $base
    cp ../"$file" .
	bro -r "$file" custom/BrowserFingerprinting/http-headers.bro
	mv http.log ../"$base"_http.log
	mv httpheaders.log ../"$base"_httpheaders.log
	rm -f *.log *.pcap
done