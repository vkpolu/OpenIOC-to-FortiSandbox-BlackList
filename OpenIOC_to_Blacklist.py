#! /usr/bin/python

import json
from base64 import b64encode
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
from ioc_writer import ioc_api


# disable selfsigned certs warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


JSON_REQUEST = {
    'login': {
        "method": "exec",
        "params": [
            {
                "url": "/sys/login/user",
                "data": [{"user": "admin","passwd": ""}]
            }
        ],
        "id": 1,
        "ver": "2.0"
    },
    'logout': {
        "method": "exec",
        "params": [{"url": "/sys/logout",}],
        "session":'',
        "id": 2,
        "ver": "2.0"
    },

    #Allow user to add/delete checksums to white/black list.
    'add_checksum_to_blacklist':{
        "method": "post",
        "params": [
            {
                "url": "/scan/policy/black-white-list",
                "list_type": "black",                           #/* The list_type should only be in ["white", "black"]. */
                "checksum_type": "md5",                         #/* The checksum_type should only be in ["md5", "sha1", "sha256", "domain"]. */
                "action": "append",                             #/* The action should only be in ["append", "replace", "clear", "download", "delete"]. */
                "upload_file": "dGhpcyBpcyBhIHRlc3QhCg==", 	    #/* encoded (base64) file contents (checksum). Max. allowed file size is 200M */
            }
        ],
        "session": "gzKj2PsMZ+4Hhs8Q9Ra+br+YStvpqWz\/8e291G1j1GI=",
        "id": 25,
        "ver":"2.2.1"
    },
}


class FSAJSON(object):
    """
    FSA JSON API
    """
    def __init__(self, host, username='admin', password='', use_https = True):

        self.username = username
        self.password = password
        self.host = host
        self.session = None

        if use_https:
            url_scheme = 'https'
        else:
            url_scheme = 'http'

        # set the json-rpc url

        self.fsa_url = url_scheme + "://" + self.host + "/jsonrpc"

    def login(self):

        payload = JSON_REQUEST['login']

        payload['params'][0]['data'][0]['user'] = self.username
        payload['params'][0]['data'][0]['passwd'] = self.password

        r = requests.post(self.fsa_url, data = json.dumps(payload), verify=False, timeout=300).json()

        code = r['result']['status']['code']
        message = r['result']['status']['message']

        if code != 0:

            self.session = None
            raise Exception("cannot login to %s using credentials [%s:%s]: %s" % (self.fsa_url, self.username, self.password, message))

        self.session = r['session']

        return self.session

    def logout(self):

        payload = JSON_REQUEST['logout']

        payload['session'] = self.session

        r = requests.post(self.fsa_url, data = json.dumps(payload), verify=False, timeout=300).json()

        code = r['result']['status']['code']
        message = r['result']['status']['message']

        if code != 0:
            raise Exception("%s: cannot logout from %s : %s" % (self.session, self.fsa_url, message))

    def addChecksumFileToBlacklist(self, checksumFileString, type):
        payload = JSON_REQUEST['add_checksum_to_blacklist']
        payload['session'] = self.session

        listLength = checksumFileString.strip('\n').split("\n")
        payload['params'][0]['upload_file'] = b64encode(checksumFileString)

        payload['params'][0]['checksum_type'] = type

        r = requests.post(self.fsa_url, data=json.dumps(payload), verify=False, timeout=300).json()

        code = r['result']['status']['code']
        message = r['result']['status']['message']

        if code != 0:
            raise Exception("Error when submitting checksum file to blacklist: %s" % message)

        print "Added %s samples to %s blacklist" % (len(listLength), type)


def main(options):
    try:
        ioc_obj = ioc_api.IOC(fn=options.file_path)
        fileSets = [{"list": [], "type": 'md5', 'xmlPath': './IndicatorItem[Context/@search = "FileItem/Md5sum"]'},
                    {"list": [], "type": 'sha1', 'xmlPath': './IndicatorItem[Context/@search = "FileItem/Sha1sum"]'},
                    {"list": [], "type": 'sha256','xmlPath': './IndicatorItem[Context/@search = "FileItem/Sha5sum"]'}]

        indicators = ioc_obj.top_level_indicator.getchildren()
        for indicator in indicators:
            for fileSet in fileSets:
                checksumItemList = indicator.xpath(fileSet["xmlPath"])
                for checksumItem in checksumItemList:
                    fileSet["list"].append(checksumItem[1].text)

        fsaInstance = FSAJSON(options.host, options.username, options.password, use_https=options.use_https)
        fsaInstance.login()

        for fileSet in fileSets:
            checksumList = fileSet["list"]
            if len(checksumList) > 0:
                checksumFileString = ""
                for checksum in checksumList:
                    checksumFileString = checksumFileString + str(checksum) + "\n"

                fsaInstance.addChecksumFileToBlacklist(checksumFileString, fileSet["type"])

        fsaInstance.logout()
    except Exception,e:
        print "ERROR: %s" % e


def makeargpaser():
    parser = argparse.ArgumentParser(description='Extract checksums from a IOC file and submit to blacklist in FortiSandbox')
    parser.add_argument('-f', '--file_path', help='File path to the IOC file, version of IOC is 1.1', required=True)
    parser.add_argument('-H', '--host', dest='host', help='FortiSandbox host address', required=True, type=str)
    parser.add_argument('-u', '--username', dest='username', help='FortiSandbox username for login, default is admin', default='admin', type=str)
    parser.add_argument('-p', '--password', dest='password', help='FortiSandbox password for login, default is empty', default='', type=str)
    parser.add_argument('--https', dest='use_https', action='store_true', default=False, help='Address of FortiSandbox is using https format, default is false')
    return parser

if __name__ == "__main__":
    p = makeargpaser()
    opts = p.parse_args()
    main(opts)



