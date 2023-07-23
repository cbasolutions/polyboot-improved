from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
import ssl
from base64 import b64encode
from html.parser import HTMLParser
import argparse
from pathlib import Path
import logging
import csv
import sys
import re
import ast


def check_python_version():
    version = sys.version_info
    return version.major >= 3 and version.minor >= 10

def polyVersion(firmware):
    return tuple(map(int, (firmware.split("."))))

class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.token = ""
        self.titleData = ""
        self.title = ""
        self.reset()

    def handle_starttag(self, tag, attrs):
        if tag == 'title':
            self.title = True
        if tag == 'meta':
            for attr,value in attrs:
                if attr == 'name' and value == 'csrf-token':
                    for content,token in attrs:
                        self.token = token
    def handle_endtag(self, tag):
        if tag == 'title':
            self.title = False
    def handle_data(self, data):
        if self.title:
            self.titleData = data

def get_creds(device_password):
    device_creds = 'Polycom:'+ device_password
    return str(b64encode(bytes(device_creds,encoding='utf-8')),encoding='utf-8', errors='strict')

def make_request(url, headers=None, data=None, method=None):
    request = Request(url, headers=headers or {}, data=data, method=method or "GET")
    try:
         response = urlopen(request, timeout=10, context=ctx)
    except HTTPError as error:
        return {'status': error.status, 'reason': error.reason, 'headers': dict(error.getheaders()),'body': error.read()}
    except URLError as error:
        return {'status': None, 'reason': error.reason, 'headers': None,'body': None}
    except TimeoutError as error:
        return {'status': error.status, 'reason': error.reason, 'headers': None,'body': None}
    else:
        return {'status': response.status, 'reason': response.reason, 'headers': dict(response.getheaders()),'body': response.read()}

#Disable SSL cert verification
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.set_ciphers('DEFAULT') #fw version 5.6 doesn't work with python 3.10+
ctx.check_hostname = False
ctx.verify_mode = ssl.VerifyMode.CERT_NONE

#Map form numbers for various functions. 
polyMapping = {
    '5.6.3.1155': {
        #Source VVX411
        'device.sntp.serverName' : '1951',
        'device.prov.serverType' : '422',
        'device.prov.serverName' : '420',
        'device.prov.user' : '428',
        'device.prov.password' : '414',
        'device.prov.redunAttemptLimit' : '416',
        'device.prov.redunInterAttemptDelay' : '418',
        'api' : '12'
    },
    '6.4.5.1210': {
        #Source VVX411/VVX450
        'device.sntp.serverName' : '2199',
        'device.prov.serverType' : '482',
        'device.prov.serverName' : '480',
        'device.prov.user' : '488',
        'device.prov.password' : '474',
        'device.prov.redunAttemptLimit' : '476',
        'device.prov.redunInterAttemptDelay' : '478',
        'api' : '16'
    },
    '6.4.3.5610': {
        #Source VVX450
        'device.sntp.serverName' : '2192',
        'device.prov.serverType' : '481',
        'device.prov.serverName' : '479',
        'device.prov.user' : '487',
        'device.prov.password' : '473',
        'device.prov.redunAttemptLimit' : '447',
        'device.prov.redunInterAttemptDelay' : '477',
        'api' : '16'
    },
    '5.9.4.3247': {
        #Source VVX411/VVX450
        'device.sntp.serverName' : '2094',
        'device.prov.serverType' : '445',
        'device.prov.serverName' : '443',
        'device.prov.user' : '451',
        'device.prov.password' : '437',
        'device.prov.redunAttemptLimit' : '438',
        'device.prov.redunInterAttemptDelay' : '441',
        'api' : '12'
    },
    '7.2.5.0085': {
        #Source Trio 8800
        'device.sntp.serverName' : '2642',
        'device.prov.serverType' : '634',
        'device.prov.serverName' : '632',
        'device.prov.user' : '640',
        'device.prov.password' : '626',
        'device.prov.redunAttemptLimit' : '628',
        'device.prov.redunInterAttemptDelay' : '630',
        'api' : '54'
    },
    '5.9.6.3432': {
        #Source Trio 8800
        'device.sntp.serverName' : '2514',
        'device.prov.serverType' : '568',
        'device.prov.serverName' : '566',
        'device.prov.user' : '574',
        'device.prov.password' : '560',
        'device.prov.redunAttemptLimit' : '562',
        'device.prov.redunInterAttemptDelay' : '564',
        'api' : '31'
    }
}

#Setup logging
argParser = argparse.ArgumentParser(prog=Path(__file__).name, usage='''
    %(prog)s [options]
    Options func, host, and password are required for single use
    Option ifile can be used with or without ofile
    Option template will create a template in for the ifile in the current working directory.''')
argParser.add_argument("--debug",action="store_true",help="print debug messages to stderr")
argParser.add_argument("-i", "--ifile", help="Input filename for bulk operations. CSV file with headers: host,password,function. Host is either host or IP")
argParser.add_argument("-f", "--function", help="Poly form-submit function to run.")
argParser.add_argument("-a", "--host", help="Hostname or IP for single operation.")
argParser.add_argument("-p", "--password", help="Password for device in single operation mode.")
argParser.add_argument("-o", "--ofile", help="Output filename for logging.")
argParser.add_argument("-t", "--template", action='store_true', help="Create CSV template for  bulk operation.")
argParser.add_argument("-d", "--data", help="Data to use in POST request. E.g. Provisioning:  {'device.prov.serverType':'2', 'device.prov.serverName':'voipt2.polycom.com/594'}") 
args = argParser.parse_args()
if args.ofile:
    logging.basicConfig(level=logging.DEBUG, filename=args.ofile, filemode="w", format="%(asctime)s %(levelname)s %(message)s")
else:
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")

if not check_python_version():
    logging.error("You must be running Python 3.10 or newer.")
    quit()

devices = []
#Analyze options, prepare for iteration
if args.host and args.password and args.function:
    devices = [{'host': args.host,'password': args.password, 'function': args.function, 'data': args.data}]
elif args.ifile:
    #Need to just open file, not in with statement. 
    with open(args.ifile, newline='', encoding='utf_8', mode='r') as csv_file:
        try:
            data = csv.DictReader(csv_file)
            devices = list(data)
            device = dict(list(devices)[0])
            if 'host' not in device.keys() or 'function' not in device.keys() or 'password' not in device.keys():
                raise csv.Error("There is an error")
        except IndexError:
            logging.error(f"The CSV file {args.ifile} is invalid.")
            argParser.print_help()
            quit()
        except csv.Error as e:
            logging.error(f"The CSV file {args.ifile} is invalid.")
            argParser.print_help()
            quit()
elif args.template:
    with open("polyboot-improved.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["host", "password", "function", "data"])
        writer.writerow(["10.0.0.1", "SomePassword", "reboot"])
        writer.writerow(["polyphone.domain", "RandomPassword", "restore"])
        writer.writerow(["polyphone.domain", "RandomPassword", "provision","{'device.prov.serverType':'2', 'device.prov.serverName':'voipt2.polycom.com/594'}"])
    quit()
else:
    argParser.print_help()
    quit()

for device in devices:
    parser = MyHTMLParser()
    device_check = make_request('https://' + device['host'] + '/Utilities/softwareUpgrade/getPhoneVersion', headers={ "Cookie": "Authorization=Basic " + get_creds(device['password'])}, method="GET")
    if device_check['reason'] == "OK":
        parser.feed(make_request('https://' + device['host'] + '/index.htm', headers={ "Cookie": "Authorization=Basic " + get_creds(device['password'])}, method="GET")['body'].decode())
        version = device_check['body'].decode()
        match polyVersion(device_check['body'].decode()):
            case _ if polyVersion(version) < polyVersion("6"):
                if device_check['headers']['Server'] == "Polycom SoundPoint IP Telephone HTTPd":
                    if device_check['headers']['Server'] == "Polycom SoundPoint IP Telephone HTTPd" and re.search("VVX", str(make_request('https://' + device['host'] + '/index.htm', headers={ "Cookie": "Authorization=Basic " + get_creds(device['password'])}, method="GET"))).group():
                        logging.info(f"{device['host']} - {device['function']} - VVX Device using older firmware, consider an upgrade: {device['host']},{device['password']},provision,\"{{'device.prov.serverType':'2', 'device.prov.serverName':'voipt2.polycom.com/594'}}\"")
                if "Trio" in parser.titleData:
                    method = "new"
                else:
                    method = "old"
            case _ if polyVersion(version) >= polyVersion("6"):
                method = "new"
            case _:
                logging.error(f"{device['host']} - {device['function']} - Device version check failed.")
                continue
        match device['function'].lower():
            case "reboot":
                function = "/Reboot"
                postData = None
            case "restore":
                function = "/Utilities/restorePhoneToFactory"
                postData = None
            case "reboot-system":
                function = "/RebootSystem"
                postData = None
            case "provision":
                if version not in polyMapping:
                    logging.error(f"{device['host']} - {device['function']} - Unknown firmware {version}, unable to provision.")
                    continue
                function = ""
                if device['data']:
                    dataDict = ast.literal_eval(device['data'])
                    postData = ""
                    for key in dataDict:
                        if postData == "":
                            postData += polyMapping[version][key] + "=" + dataDict[key]
                        else:
                            postData += "&" + polyMapping[version][key] + "=" + dataDict[key]
                    postData = postData.encode("utf-8")
                else: 
                    logging.error(f"{device['host']} - {device['function']} - Provision function used and data element is not set.")
                    continue
            case _:
                logging.error(f"{device['host']} - {device['function']} - Function not supported.")
                continue
        match method:
            case "old":
                process = make_request('https://' + device['host'] + '/form-submit' + function, headers={ "Cookie": "Authorization=Basic " + get_creds(device['password']) }, data=postData, method="POST")
                if process['reason'] == "OK" and ( process['body'].decode() == "CONF_CHANGE" or device['function'].lower() == 'reboot' or device['function'].lower() == 'restore' ):
                    if args.debug:
                        logging.debug(f"{device['host']} - {device['function']}: {process['status']} - {process['reason']} - {process['body'].decode()}")
                    else:
                        logging.info(f"{device['host']} - {device['function']}: {process['status']} - {process['reason']}")
                else:
                    if args.debug:
                        logging.debug(f"{device['host']} - {device['function']}: {process['status']} - {process['reason']} - {process['body'].decode()}")
                    else:
                        logging.error(f"{device['host']} - {device['function']}: {process['status']} - {process['reason']}")
            case "new":
                auth = make_request('https://' + device['host'] + '/form-submit/auth.htm', headers={'Authorization': 'Basic ' + get_creds(device['password']) }, method="POST")
                if auth['reason'] == "OK":
                    session_cookie = "".join(filter(lambda a: 'session' in a, auth['headers']['Set-Cookie'].split(';')))
                    if not session_cookie.startswith("session"):
                        if args.debug:
                            logging.debug(f"{device['host']} - {device['function']}: {auth['status']} - {auth['reason']} - {auth['headers']['Set-Cookie']}")
                        else:
                            logging.error(f"{device['host']} - {device['function']}: {auth['status']} - {auth['reason']} - No session cookie")
                        continue
                    else:
                        csrf_request = make_request('https://' + device['host'] + '/index.htm', headers = { 'Authorization': 'Basic ' + get_creds(device['password']), "Cookie": session_cookie })
                        if csrf_request['reason'] == "OK":
                            parser.feed(csrf_request['body'].decode())
                            if parser.token == "":
                                if args.debug:
                                    logging.debug(f"{device['host']} - {device['function']} - CSRF token - No token available")
                                process = make_request('https://' + device['host'] + '/form-submit' + function, headers = {'Authorization': 'Basic ' +  get_creds(device['password']), "Cookie": session_cookie }, data=postData, method="POST")
                                if process['reason'] == "OK" and (( process['body'].decode() == "CONF_CHANGE" and device['function'] == "provision") or device['function'] == "restore" or device['function'] == "reboot" ):
                                    if args.debug:
                                        logging.debug(f"{device['host']} - {device['function']}: {process['status']} - {process['reason']} - {process['body'].decode()}")
                                else:
                                    logging.error(f'{device["host"]} - {device["function"]}: {process["status"]} - {process["reason"]}')
                            else:
                                process = make_request('https://' + device['host'] + '/form-submit' + function, headers = {'Authorization': 'Basic ' +  get_creds(device['password']), "Cookie": session_cookie, "anti-csrf-token": parser.token }, data=postData, method="POST")
                                if process['reason'] == "OK" and (( process['body'].decode() == "CONF_CHANGE" and device['function'] == "provision") or device['function'] == "restore" or device['function'] == "reboot" ):
                                    if args.debug:
                                        logging.debug(f"{device['host']} - {device['function']}: {process['status']} - {process['reason']} - {process['body'].decode()}")
                                else:
                                    logging.error(f'{device["host"]} - {device["function"]}: {process["status"]} - {process["reason"]}')
            case _:
                logging.error(f"{device['host']} - {device['function']} - No method found.")
    elif device_check['reason'] == "Unauthorized":
        logging.error(f"{device['host']} - {device['function']} - {device_check['status']} - {device_check['reason']}")
        continue
    else:
        logging.error(f"{device['host']} - {device['function']} - {str(device_check['reason'])}")
        continue
