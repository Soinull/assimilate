# Assimilate
Assimilate is a series of scripts for using the Naïve Bayes algorithm to find potential malicious activity in HTTP headers.  Assimilate is designed as a cyber hunting tool to augment human cyber hunting efforts.

**Assimilate-train.py** will ingest malicious and non-malicious bro_http_header logs and use the Naïve Bayes algorithm to build a model to find potentially malicious HTTP traffic from subsequent bto_http_header logs.

**Assimilate-assess.py** will load the created model and process either a single bro_http_header file or a directory of them and call out suspicious log entries for further analysis.

**Assimilate_utils.py** contains a modified version of Brologreader originally written by Mike Sconzo.  The original source for Brologreader can be found at github.com/ClickSecurity/data_hacking and all credit to Mike for the excellent Bro log parser code.

**Http-headers.bro** is a Bro module that will extract a single string http header from HTTP sessions using Bro.  Again the original code is credit to Mike Sconzo and be found at the same link just above.  This version has been modified to also keep track of Bro's unique session identifier so that any suspicious records found can easily be cross-referenced to the rest of the Bro data on the suspect sessions.

**Pcap_to_bro.sh** is a simple shell script designed to take raw pcaps and run them through Bro with the -r option and rename the Bro HTTP and HTTP_Header logs files for use in both training and running Assimilate against.

## Prereqs

You'll need a few python libraries installed for assimilat to work properly.

	% sudo pip install scikit-learn
	% pip install sklearn-extensions pandas
	
## Quick start: training models
	% ./assimilate-train.py -n /path_to_folder_with_normal_bro_http_header_logs -m /path_to_folder_with_malicious_bro_http_header_logs
	
## Quick start: looking for suspicious entries
	% ./assimilate-assess.py -f single_bro_http_header_file.log
	
	OR
	
	% ./assimilate-assess.py -d directory_of_bro_http_header_files
	
It is highly recommended to add -o results.txt to capture the resulting suspicious file.  Analysis can take a bit depending on the size of your model and the amount of Bro logs to process so if you are concerned it's not doing anything you can also use -v to have assimilate_assess.py report progress as it works.

## More Info

I'll be giving a talk on using Assimilate for cyber hunting at the SANs Threat Hunting and Incident Response summit in New Orleans on Apr 18-19.  I'll post the deck from that talk after the event.
