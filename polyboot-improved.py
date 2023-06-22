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

def check_python_version():
    version = sys.version_info
    return version.major >= 3 and version.minor >= 10

class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        MyHTMLParser.token = ""
        self.reset()

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            for attr,value in attrs:
                if attr == "name" and value == "csrf-token":
                    for content,token in attrs:
                        if content == "content":
                            MyHTMLParser.token = token

def get_creds(device_password):
    device_creds = 'Polycom:'+ device_password
    return str(b64encode(bytes(device_creds,encoding='utf-8')),encoding='utf-8', errors='strict')

def make_request(url, headers=None, data=None, method=None):
    request = Request(url, headers=headers or {}, data=data, method=method or "GET")
    try:
         with urlopen(request, timeout=10, context=ctx) as response:
             return response.read(), response
    except HTTPError as error:
        return error.status, error.reason
    except URLError as error:
        return error.reason
    except TimeoutError:
        return "Request timed out"

#Disable SSL cert verification
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.VerifyMode.CERT_NONE

#Setup logging
argParser = argparse.ArgumentParser(prog=Path(__file__).name, usage='''
    %(prog)s [options]
    Options func, host, and password are required for single use
    Option ifile can be used with or without ofile
    Option template will create a template in for the ifile in the current working directory.''')
argParser.add_argument("-i", "--ifile", help="Input filename for bulk operations. CSV file with headers: host,password,function. Host is either host or IP")
argParser.add_argument("-f", "--function", help="Poly form-submit function to run.")
argParser.add_argument("-a", "--host", help="Hostname or IP for single operation.")
argParser.add_argument("-p", "--password", help="Password for device in single operation mode.")
argParser.add_argument("-o", "--ofile", help="Output filename for logging.")
argParser.add_argument("-t", "--template", action='store_true', help="Create CSV template for  bulk operation.")
args = argParser.parse_args()
if args.ofile:
    logging.basicConfig(level=logging.INFO, filename=args.ofile, filemode="w", format="%(asctime)s %(levelname)s %(message)s")
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

if not check_python_version():
    logging.error("You must be running Python 3.10 or newer.")
    quit()

devices = []
#Analyze options, prepare for iteration
if args.host and args.password and args.function:
    devices = [{"host": args.host,"password": args.password, "function": args.function}]
elif args.ifile:
    #Need to just open file, not in with statement. 
    with open(args.ifile, newline='', encoding='utf_8', mode='r') as csv_file:
        try:
            data = csv.DictReader(csv_file)
            devices = list(data)
            device = dict(list(devices)[0])
            if "host" not in device.keys() or "function" not in device.keys() or "password" not in device.keys():
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
        writer.writerow(["host", "password", "function"])
        writer.writerow(["10.0.0.1", "SomePassword", "reboot"])
        writer.writerow(["polyphone.domain", "RandomPassword", "restore"])
        writer.writerow(["polyTriophone.domain", "RandomPassword", "reboot-system"])
    quit()
else:
    argParser.print_help()
    quit()

for device in devices:
    match device["function"].lower():
        case "reboot":
            function = "Reboot"
        case "restore":
            function = "Utilities/restorePhoneToFactory"
        case "reboot-system":
            function = "RebootSystem"
        case _:
            logging.error(device["host"] + " " + device["function"] + " Error function not supported. Please use either reboot, reboot-system (Trio), or restore")
            #Enhance to put supported functions into help statement and execute that.
    #Try Older Firmware Method
    fw5 = make_request('https://' + device["host"] + '/form-submit/' + function, headers={ "Cookie": "Authorization=Basic " + get_creds(device["password"]) }, method="POST")
    if isinstance(fw5, (str, list, tuple)):
        if str(fw5[0]) == '401':
            logging.warning(device["host"] + " " + device["function"] + " " + str(fw5))
            #Returns 401 if version 6 firmware.
            logging.info(device["host"] + " " + device["function"] + " Trying v6 firmware method.")
            fw6_auth = make_request('https://' + device["host"] + '/form-submit/auth.htm', headers={'Authorization': 'Basic ' + get_creds(device["password"]) }, method="POST")
            if "SUCCESS" in str(fw6_auth[0]):
                session_cookie = "".join(filter(lambda a: 'session' in a, fw6_auth[1].getheader("Set-Cookie").split(';')))
                fw6_CSRF = make_request('https://' + device["host"] + '/index.htm', headers = { 'Authorization': 'Basic ' + get_creds(device["password"]), "Cookie": session_cookie })
                if fw6_CSRF[1].status == 200:
                    parser = MyHTMLParser()
                    parser.feed(str(fw6_CSRF[0]))
                    if parser.token == "":
                        logging.info(device["host"] + " " + device["function"] + " CSRF token - No token available")
                        make_request('https://' + device["host"] + '/form-submit/' + function, headers = {'Authorization': 'Basic ' +  get_creds(device["password"]), "Cookie": session_cookie }, method="POST")
                    else:
                        make_request('https://' + device["host"] + '/form-submit/' + function, headers = {'Authorization': 'Basic ' +  get_creds(device["password"]), "Cookie": session_cookie, "anti-csrf-token": parser.token }, method="POST")
            else:
                logging.error(device["host"] + " " + device["function"] + " " + str(fw6_auth[0]))
        if fw5[0] == 200:
            logging.info(device["host"] + " " + device["function"] + "SUCCESS")
            continue
    else:
        logging.error(device["host"] + " " + device["function"] + " " + str(fw5))
