import os
import requests
import time
from datetime import datetime
from colorama import Fore

report = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <style>h1 {text-align: center;}</style>
</head>
<body>
    <h1>FIREWALL REPORT</h1>
    <br>
    <H3>WAF NAME: </H3>
    //waf name//
    <h3>DOMAIN NAME: </h3>
    //domain//
    <h3>HTTPX REPORT: </h3>
    //httpx//
    <h3>TRACEROUTE REPORT: </h3>
    //traceroute//
    <h3>RATE LIMIT(req/s): </h3>
    //rate limit//
    <h3>Time being blocked</h3>
    //blocked//
</body>
</html>"""

def time_blocked(url, domain):
    time_started = datetime.now()
    time_started = time_started.strftime("%H:%M:%S")
    while True:
        if requests.get(url).status_code != 403:
            print(Fore.GREEN + 'UNBLOCKED!' + Fore.RESET)
            time_finished = datetime.now()
            time_finished = time_finished.strftime("%H:%M:%S")
            return f'Time started: {time_started}<br>Time finished: {time_finished}'
        time.sleep(3)
        print(f'{Fore.GREEN}[+]{Fore.YELLOW} Probing...{Fore.RESET}')

def generate_wordlist(domain):
    i = 100
    while True:
        if i == 0:
            print(f'{Fore.GREEN}[+]{Fore.YELLOW} Wordlist Generated!{Fore.RESET}')
            break
        else:
            open(f'.{domain}/wordlist', 'a').write('\n' + 'INFOINFOINFOINFOINFOINFOINFOINFO')
            i=i-1
        
def tryratelimit(url, domain):
    print(f'{Fore.GREEN}[+]{Fore.YELLOW} Trying Rate limit...{Fore.RESET}')
    try:
        open(f'.{domain}/wordlist')
    except:
        generate_wordlist(domain)

    control = 100
    index = 1
    while True:
        if index > control:
            return 'NO RATE LIMIT!'
        os.system(f'sudo ffuf -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36" -s -rate {index} -u {url}/FUZZ -w .{domain}/wordlist > .{domain}/fuzz')
        if requests.get(url).status_code == 403:
            return str(index)
        else:
            index+=1
            print(f'{Fore.GREEN}[+]{Fore.YELLOW} trying rate limit {Fore.BLUE}{index}req/s{Fore.RESET}')
def httpx(domain):
    print(f'{Fore.GREEN}[+] {Fore.YELLOW}Httpx... {Fore.RESET}')
    os.system(f'sudo httpx -td -u {domain} -nc > .{domain}/httpx')
    return 'OK'

def wafcollect(domain):
    print(f'{Fore.GREEN}[+]{Fore.YELLOW} WAF...{Fore.RESET}')
    os.system(f'sudo wafw00f {domain} --no-color | grep "is behind" >  .{domain}/waf')
    return 'OK'

def traceroute(domain):
    print(f'{Fore.GREEN}[+]{Fore.YELLOW} Traceroute...{Fore.RESET}')
    os.system(f'sudo traceroute -4 {domain} > .{domain}/traceroute')
    return 'OK'

url = input(f'{Fore.GREEN}URL{Fore.BLUE} OF THE TARGET  >> {Fore.CYAN} ')
domain = url.replace('https://', '').replace('http://', '')

try:
    os.mkdir(f'.{domain}')
except:
    print(f'{Fore.RED}[-]{Fore.YELLOW} ERROR creating .{domain} {Fore.RESET}')
try:
    req = requests.get(url)
    print(f'{Fore.GREEN}[+]{Fore.YELLOW} CONNECTION VERIFIED! Verifing status code')
    original_status_code = req.status_code
    print(Fore.CYAN, original_status_code, Fore.RESET)
    if original_status_code != 403:
        print(f'{Fore.GREEN}[+] {Fore.YELLOW}OK!{Fore.RESET}')
    else:
        print(f'{Fore.RED}[-] {Fore.RESET}CANNOT TEST 403 STATUS CODE, ABORTING!{Fore.RESET}')
        exit()

except Exception as e:
    print(f'{Fore.RED}[-] {Fore.YELLOW}ERROR REQUESTING...{Fore.RESET}', e)
    exit()
print(f'{Fore.GREEN}[+] {Fore.YELLOW}Collecting information about domain...{Fore.RESET}')
print(wafcollect(domain=domain))
print(traceroute(domain=domain))
print(httpx(domain=domain))

print(f'{Fore.GREEN}[+] {Fore.YELLOW}INFO COLLECTED{Fore.RESET}')
print(f'{Fore.GREEN}[+] {Fore.YELLOW}Checking rate limit...{Fore.RESET}')
resp = tryratelimit(url=url, domain=domain)
if resp != 'NO RATE LIMIT!':
    print(f'{Fore.GREEN}[+]{Fore.YELLOW} Checking time blocked...{Fore.RESET}')
    time_blocked_in = time_blocked(url, domain)
else:
    print(f'{Fore.GREEN}[+] {Fore.YELLOW}NO RATE LIMIT!{Fore.RESET}')
    time_blocked_in = 'No Rate Limit!'

print(f'{Fore.GREEN}[+] Creating report!{Fore.RESET}')

try:
    waf = open(f'.{domain}/waf').read().split('is behind')[1].replace('\n', '<br>')
except:
    waf = 'No waf info!'

try:
    traceroute_in = open(f'.{domain}/traceroute').read().replace('\n', '<br>')
except:
    traceroute_in = 'No traceroute info!'

try:
    httpx_in = open(f'.{domain}').replace('\n', '<br>')
except:
    httpx_in = 'No httpx info!'

report = report.replace('//waf name//', waf).replace('//domain//', domain).replace('//httpx//', httpx_in).replace('//traceroute//', traceroute_in).replace('//blocked//', time_blocked_in).replace('//rate limit//', resp)

open('report.html', 'w').write(report)