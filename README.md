# OpenIOC-to-FortiSandbox-BlackList
This script takes v1.1 OpenIOC file as input and extract checksums from it. Checksums are then submitted to FortiSandbox blacklist. Each different file in the OpenIOC has to be a separate indicator with file checksum as indicatorItem of this indicator.

## DESCRIPTION

This script takes v1.1 OpenIOC file as input and extract checksums from it. Checksums are then submitted to FortiSandbox blacklist. Each different file in the OpenIOC has to be a separate indicator with file checksum as indicatorItem of this indicator.


## PREREQUISITES    
Python 2.7.3+    
requests    
ioc_writer

 

## USAGE

python OpenIOC_to_Blacklist.py -h
usage: OpenIOC_to_Blacklist.py [-h] -f FILE_PATH -H HOST [-u USERNAME]
                               [-p PASSWORD] [--https]

Extract checksums from a IOC file and submit to blacklist in FortiSandbox

optional arguments:
  -h, --help            show this help message and exit
  -f FILE_PATH, --file_path FILE_PATH
                        File path to the IOC file, version of IOC is 1.1
  -H HOST, --host HOST  FortiSandbox host address
  -u USERNAME, --username USERNAME
                        FortiSandbox username for login, default is admin
  -p PASSWORD, --password PASSWORD
                        FortiSandbox password for login, default is empty
  --https               Address of FortiSandbox is using https format, default
                        is false


This script takes v1.1 OpenIOC files.  To convert v1.0 OpenIOC to v1.1, please refer to https://github.com/mandiant/ioc_writer/tree/master/ioc_writer/scripts/openioc_10_to_11.py
