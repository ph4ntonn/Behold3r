# Just4fun,don't be so serious XD
# coding: utf-8
from tld import get_fld, get_tld
from redis import Redis
from termcolor import colored
from config import *
from queue import Queue
from Email import *
import argparse
import time
import requests
import sys
import re
import threading
import os
import math
import asyncio
import aiohttp
import execjs


Author = "Aiden Qi(@ph4ntom)"
Version = '1.2'
Email = "ph4ntom11235@gmail.com"


def args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-u', '--url',
                       dest="url",
                       help="Domain that need to be diged",
                       required=False)
    group.add_argument('-s', '--search',
                       dest="search",
                       help="Search the data of the given url",
                       default="",
                       required=False)
    parser.add_argument('-c', '--confirm',
                        dest="confirm",
                        help="Test if domain is still alive",
                        default=False,
                        action="store_true",
                        required=False)
    parser.add_argument('-r', '--redis',
                        dest='redis',
                        help="Use the redis to reserve the result",
                        action="store_true",
                        default=False,
                        required=False)
    parser.add_argument('-t', '--timeout',
                        dest='timeout',
                        help="Second(s) when testing if domain alive",
                        default=5,
                        required=False)
    parser.add_argument('-e', '--email',
                        dest='email',
                        help='The email to receive the monitor data',
                        default='',
                        required=False)
    parser.add_argument('-d', '--domains',
                        dest='monitor_domain',
                        help='Domains to monitor',
                        default='',
                        required=False)
    parser.add_argument('-f', '--flush',
                        dest='flush',
                        help='Clear all monitored domains',
                        default='',
                        required=False)
    parser.add_argument('-p', '--pop',
                        dest='pop',
                        help='Remove specific monitoring domain',
                        default='',
                        required=False)
    parser.add_argument('-l', '--listing',
                        dest='listing',
                        help='Show all domain currently being monitored',
                        default=False,
                        action="store_true",
                        required=False)
    parser.add_argument('-o','--output',
                        dest='output',
                        help='export subdomains\' data file',
                        default=False,
                        action="store_true",
                        required=False)
    parser.add_argument('-x',
                        dest='execute',
                        help='Don\'t use this option!!!!',
                        action="store_true",
                        required=False
                        )
    return parser.parse_args()


def banner():
    print(colored(
        '''
    ______      _           _     _  _____      
    | ___ \    | |         | |   | ||____ |     
    | |_/ / ___| |__   ___ | | __| |    / /_ __ 
    | ___ \/ _ \ '_ \ / _ \| |/ _` |    \ \ '__|
    | |_/ /  __/ | | | (_) | | (_| |.___/ / |   
    \____/ \___|_| |_|\___/|_|\__,_|\____/|_| 
                                         
        ''', "yellow"))
    print(colored("            Author: {}".format(Author), "red"))
    print(colored("            Version: {}", "red").format(Version))
    print(colored("            Email: {}", "red").format(Email))


# Functions below are control functions


def conn_redis():
    return Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DATABASE)


def test_conn(conn):
    conn.set("Beholder", "Beholder")
    conn.delete("Beholder")


def check_given_url(url):
    try:
        TLD = get_fld(url)
        return TLD
    except Exception as e:
        print(colored("The format of given url is WRONG!!! It must like (http,https)://example(.com,.cn,.net,etc...)", "red"))
        sys.exit(1)


def check_diff(old_data, new_data):
    changed_data = [i for i in new_data if i not in old_data]
    return changed_data


def print_status(status, source):
    if status == 'start':
        print(colored("Searching the subdomains through {}....... ".format(source), "green"))
    elif status == 'error':
        print(colored("----------{} seems down,Skipping....----------".format(source), "red"))
    else:
        pass


def del_dup(data):
    data = set(data)
    return data


# Control functions end

# Functions below are operating functions

# Do something?
def someoper(url):
    TLD = check_given_url(url)
    dnsdump = Dnsdumpster(TLD)
    dnsscan = Dnsscan(TLD)
    threatcrowd = Threatcrowd(TLD)
    print(colored("Some operations may take a few minutes,please wait......", "green"))
    subdomain = check_subdomain_bycrt(TLD)
    subdomain += check_subdomain_byip138(TLD)
    subdomain += dnsdump.worker()
    subdomain += dnsscan.worker()
    subdomain += threatcrowd.worker()
    subdomain = del_dup(subdomain)
    return subdomain


# Email functions
def email_prepare_163(data_ready):
    changed_data = {}
    for domain in data_ready:
        new_data = search_sub(domain)
        new_data = list(map(lambda x: str(x, "utf-8"), new_data))
        old_data = list(map(lambda x: str(x, "utf-8"), data_ready[domain]))
        changed_data[domain] = check_diff(old_data, new_data)
    send_163_email(changed_data)


def email_prepare_qq(data_ready):
    changed_data = {}
    for domain in data_ready:
        new_data = search_sub(domain)
        new_data = list(map(lambda x: str(x, "utf-8"), new_data))
        old_data = list(map(lambda x: str(x, "utf-8"), data_ready[domain]))
        changed_data[domain] = check_diff(old_data, new_data)
    send_qq_email(changed_data)


# Saving data to redis
def saving(data, conn, url):
    try:
        print(colored("[*]Checking if data has existed.....", "green"))
        try:
            if conn.exists(url):
                print(colored("[*]Data has existed,clearing.....", "red"))
                conn.delete(url)
        except:
            print(colored("[*]Data doesn't exist,saving.....", "green"))
        if confirm is False:
            print(colored("[*]All data have shown as below.....", "green"))
            for everyone in data:
                print(everyone)
        for everyone in data:
            conn.lpush(url, everyone)
        print(colored("[*]Saving data successfully", "green"))
    except Exception as e:
        print(e)


# Check if subdomains alive
def prepare_test(domains):
    global domains_alive
    tasks = []
    loop = asyncio.get_event_loop()
    print(colored("---------Testing----------", "green"))
    for domain in domains:
        if "http://" not in domain and "https://" not in domain:
            domain = "http://" + domain
        task = asyncio.ensure_future(check_alive(domain))
        tasks.append(task)
    loop.run_until_complete(asyncio.wait(tasks))

    domains_alive = list(set(domains_alive))
    return domains_alive


async def check_alive(domain):
    global doamins_alive
    conn = aiohttp.TCPConnector(verify_ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        try:
            async with session.get(domain, timeout=10) as resp:
                statuscode = resp.status
                if statuscode in [200, 443, 302]:
                    domains_alive.append(domain)
        except:
            pass


# Search given domain's subdomain in redis
def search_sub(url, output):
    conn = conn_redis()
    try:
        length = conn.llen(url)
        results = conn.lrange(url, 0, int(length))
        print(colored("----------Found {} records!----------".format(length),"green"))
        print(colored("----------The subdomains of given url are shown as below----------", "green"))
        for i in results:
            print(i.decode('utf-8'))
        print(colored("----------That's all!!!!!!----------", "green"))
        export_file(True, results, url, output)
        return list(results)
    except Exception as e:
        print(e)
        print(colored("Cannot find any data!", "red"))


# Export subdomains as .txt file
def export_file(flag, subdomains, url, output):
    if output:
        filename = get_tld(url, as_object=True)
        filename = filename.domain
        try:
            with open("{}.txt".format(filename), "a") as subdomain:
                for i in subdomains:
                    if flag:
                        subdomain.write(i.decode('utf-8')+"\n")
                    else:
                        subdomain.write(i+"\n")
            print(colored("[*]Export sudomain file successfully, check the {}.txt!".format(filename), "green"))
        except Exception as e:
            print(e)
            print(colored("[*]Cannot export subdomain as .txt file", "red")) 


# Flush all monitored domains
def flush_all(target):
    if target == '163':
        temp = open("mon_163.txt", "w")
        temp.close()
        print(colored("Clear successfully!!!", "green"))
    elif target == 'qq':
        temp = open("mon_qq.txt", "w")
        temp.close()
        print(colored("Clear successfully!!!", "green"))
    else:
        print(colored("Warnning!!:Unsupported method!!!!", "red"))
        sys.exit(1)
    sys.exit(0)


# List all monitored domains
def list_all():
    try:
        with open("mon_163.txt", "r") as mon:
            data = mon.readlines()
        print(colored("----------Here are domains being monitored under *@163.com---------", "green"))
        for domain in data:
            print(domain.strip("\n"))
    except FileNotFoundError:
        print(colored("-------mon_163.txt cannot be found,please make sure if there are any domains under monitoring-------", "red"))
    try:
        with open("mon_qq.txt", "r") as mon:
            data = mon.readlines()
        print(colored("----------Here are domains being monitored under *@qq.com---------", "green"))
        for domain in data:
            print(domain.strip("\n"))
    except FileNotFoundError:
        print(colored("-------mon_qq.txt cannot be found,please make sure if there are any domains under monitoring-------", "red"))
    sys.exit(0)


# Pop one specific monitored domain
def pop_domain(target, email):
    if email == '163':
        with open("mon_163.txt", "r") as mon:
            data = mon.readlines()
        if target+"\n" in data:
            data.remove(target+"\n")
            print(colored("Successfully remove given domain", "green"))
            with open("mon_163.txt", "w") as mon:
                for domain in data:
                    mon.write(domain)
            sys.exit(0)
        else:
            print(colored("Given domain not found!!!!", "red"))
            sys.exit(1)
    elif email == 'qq':
        with open("mon_qq.txt", "r") as mon:
            data = mon.readlines()
        if target+"\n" in data:
            data.remove(target+"\n")
            print(colored("Successfully remove given domain", "green"))
            with open("mon_qq.txt", "w") as mon:
                for domain in data:
                    mon.write(domain)
            sys.exit(0)
        else:
            print(colored("Given domain not found!!!!", "red"))
            sys.exit(1)


# Functions below are subdomains' discovering functions
def check_subdomain_bycrt(url):
    print_status('start', 'Crt.sh')
    search_string = "%25."+str(url)
    result = []
    try:
        response = requests.get("http://crt.sh/?Identity={}&output=json".format(search_string), timeout=5)
        if response.status_code == 200:
            for domain in response.json():
                result.append(domain['name_value'])
        else:
            pass
    except:
        print_status('error', 'Crt.sh')
    return result


def check_subdomain_byip138(url):
    print_status('start', 'IP138')
    pattern = r'_blank">([A-Za-z0-9.]*)</a></p>'
    search_result = []
    try:
        response = requests.get("https://site.ip138.com/{}/domain.htm".format(url), timeout=10)
        if response.status_code == 200:
            search_result = re.findall(pattern, response.text)
        else:
            pass
    except TimeoutError:
        print_status('error', 'IP138')
    return search_result


class Dnsdumpster:
    def __init__(self, domain):
        self.domain = domain
        self.url = "https://dnsdumpster.com/"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.8',
              'Accept-Encoding': 'gzip',
        }
        self.sender = requests.Session()

    def send_req(self, method, param=None):
        param = param or {}
        headers = dict(self.headers)
        headers['Referer'] = "https://dnsdumpster.com/"
        try:
            if method == 'GET':
                response = self.sender.get(self.url,
                                           headers=headers,
                                           timeout=10)
            else:
                response = self.sender.post(self.url,
                                            data=param,
                                            headers=headers,
                                            timeout=10)
        except Exception as e:
            print(colored("Searching through Dnsdumpster timeout!", "red"))
            response = None
        return response.text

    def getcsrf(self, response):
        csrf = re.compile('<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">', re.S)
        token = csrf.findall(response)[0]
        return token.strip()

    def analyze(self, data):
        table_searcher = re.compile('<a name="hostanchor"><\/a>Host Records.*?<table.*?>(.*?)</table>', re.S)
        link_searcher = re.compile('<td class="col-md-4">(.*?)<br>', re.S)
        subdomains = []
        try:
            target_table = table_searcher.findall(data)[0]
        except IndexError:
            target_table = ''
        try:
            target_subdomains = link_searcher.findall(target_table)
        except Exception as e:
            print(e)
            target_subdomains = []
        temp = list(set(target_subdomains))
        for subdomain in temp:
            subdomain = subdomain.strip("\n").strip()
            if subdomain.endswith(self.domain) and subdomain != self.domain:
                subdomains.append(subdomain)
            else:
                continue
        return subdomains

    def worker(self):
        try:
            subdomains = []
            print_status('start', 'Dnsdumpster')
            init = self.send_req("GET", self.url)
            token = self.getcsrf(init)
            param = {'csrfmiddlewaretoken': token, 'targetip': self.domain}
            result = self.send_req("POST", param)
            subdomains = self.analyze(result)
        except:
            print_status('error', 'Dnsdumpster')
        return subdomains


class Dnsscan:
    def __init__(self, domain):
        self.domain = domain
        self.url = "https://www.dnsscan.cn/dns.html"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        self.sender = requests.Session()

    def send_req(self, method, param=None):
        param = param or {}
        headers = dict(self.headers)
        headers['Referer'] = "https://www.dnsscan.cn/dns.html"
        headers['Origin'] = "https://www.dnsscan.cn"
        try:
            if method == "GET":
                response = self.sender.get(self.url,
                                           headers=headers,
                                           timeout=10)
            elif method == "POST":
                response = self.sender.post(self.url,
                                            headers=headers,
                                            data=param,
                                            timeout=10)
        except Exception as e:
            print(e)
            response = None
        return response.text

    def find_amount(self, data):
        try:
            finder = re.compile('查询结果为:(.*)条', re.S)
            amount = finder.findall(data)[0]
            return math.floor(int(amount)/20)
        except Exception as e:
            print(e)

    def analyze(self, data):
        try:      
            temp = []
            searcher = re.compile(r'<a href="([a-zA-Z0-9./:]*)" rel="nofollow"', re.S)
            temp = searcher.findall(data)
        except Exception as e:
            print(e)
        return list(temp)

    def worker(self):
        try:
            subdomains = []
            print_status('start', 'Dnsscan')
            param = {"ecmsfrom": "102.111.111.111", "show": r"%E5%9B%BD%E5%86%85%E6%9C%AA%E8%83%BD%E8%AF%86%E5%88%AB%E7%9A%84%E5%9C%B0%E5%8C%BA", "classid": "0", "keywords": self.domain}
            response = self.send_req("POST", param)
            amount = self.find_amount(response)
            subdomain_1 = self.analyze(response)
            subdomains += subdomain_1
            for i in range(amount):
                self.url = "https://www.dnsscan.cn/dns.html?keywords={}&page={}".format(self.domain, i+2)
                response = self.send_req("POST", param)
                subdomain = self.analyze(response)
                subdomains += subdomain
        except:
            print_status('error', 'Dnsscan')
        return subdomains


class Threatcrowd:
    def __init__(self, domain):
        self.domain = domain
        self.infourl = "https://www.threatcrowd.org"
        self.url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        self.sender = requests.Session()

    def get_first_cookie(self):
        try:
            response = self.sender.get(self.infourl,
                                       headers=self.headers,
                                       timeout=10)
            return response
        except Exception as e:
            print(e)
            return None

    def get_second_cookie(self, params, key):
        url = self.infourl + params["url_suffix"]
        post_params = {}
        post_params["jschl_answer"] = key
        post_params["r"] = params['first_param']
        post_params["jschl_vc"] = params['second_param']
        post_params["pass"] = params['third_param']
        try:
            print(colored("[*]Bypassing cloudflare protection...Please wait...", "green"))
            time.sleep(5)
            response = self.sender.post(url,
                                        headers=self.headers,
                                        data=post_params,
                                        timeout=10)
            return response
        except Exception as e:
            print(e)
            return None

    def get_key(self, text):
        try:
            pattern = re.compile('setTimeout\(function\(\)\{(.*?)f.action \+= location.hash;', re.S)
            code = pattern.findall(text)
            code = re.sub('\s+(t = document.*?);\s+;', '', code[0], flags=re.S)
            code = re.sub('a.value', 'value', code)
            code = re.sub('t.length', '19', code)
            code = 'function test(){' + code.strip() + ';return value;}'
            result = execjs.compile(code)
            key = result.call('test')
            return key
        except Exception as e:
            print(e)

    def get_params(self, text):
        try:
            final_dict = {}
            pattern = re.compile('<form id="challenge-form" action="(.*)" method="POST"', re.S)
            final_dict["url_suffix"] = pattern.findall(text)[0]
            pattern = re.compile('<input type="hidden" name="r" value="(.*)"></input>', re.S)
            final_dict["first_param"] = pattern.findall(text)[0]
            pattern = re.compile('<input type="hidden" name="jschl_vc" value="(.*)"/>')
            final_dict["second_param"] = pattern.findall(text)[0]
            pattern = re.compile('<input type="hidden" name="pass" value="(.*)"/>') 
            final_dict["third_param"] = pattern.findall(text)[0]
            return final_dict
        except Exception as e:
            print(e)
            return None

    def send_req(self, domain):
        try:
            response = self.sender.get(self.url.format(domain),
                                       headers=self.headers,
                                       timeout=10)
        except Exception as e:
            response = None
        return response.json()

    def worker(self):
        try:
            subdomains = []
            print_status("start", "Threatcrowd")
            response = self.get_first_cookie()
            key = self.get_key(response.text)
            params = self.get_params(response.text)
            response = self.get_second_cookie(params, key)
            response = self.send_req(self.domain)
            for domains in response['subdomains']:
                subdomains.append(domains)
            return subdomains
        except Exception as e:
            print(e)
            print_status('error', "Threatcrowd")


# Discovering functions end

# Main function start


if __name__ == "__main__":
    redis = args().redis
    url = args().url
    search = args().search
    conn = conn_redis()
    ready = Queue()
    domains_alive = []
    confirm = args().confirm
    timeout = int(args().timeout)
    email = args().email
    monitor_domain = args().monitor_domain
    execute = args().execute
    path = os.getcwd()
    flush = args().flush
    pop = args().pop
    listing = args().listing
    output = args().output

    banner()

    if redis and search:
        print("Beholder.py: error: argument -s/--search: not allowed with argument -r/--redis")
        sys.exit(1)
    else:
        pass

    if search:
        search_sub(search, output)
    else:
        pass

    if listing:
        list_all()
    else:
        pass

    if flush != '':
        flush_all(flush)
    else:
        pass

    if pop != '' and email in ['163', 'qq']:
        pop_domain(pop, email)
    elif pop == '':
        pass
    else:
        print(colored("Warnning!!:Unsupported method!!!!", "red"))
        sys.exit(1)

    if (email != '' and monitor_domain == '') or (email == '' and monitor_domain != ''):
        print(colored("Warnning!:Option -e should be used with option -d", "red"))
        sys.exit(1)
    elif(email != '' and monitor_domain != '') and (redis or url or confirm or search != ""):
        print(colored("Warning!:Option -e/-d/-r can only be used without additional options"))
        sys.exit(1)
    elif email != '' and monitor_domain != '':
        if email == "163":
            try:
                with open("mon_163.txt", "a") as mon:
                    mon.write(monitor_domain+"\n")
                print(colored("Successfully added!!!!", "green"))
                sys.exit(0)
            except IOError:
                print(colored("Warnning!:Fail to add domain!", "red"))
                sys.exit(1)
        elif email == "qq":
            try:
                with open("mon_qq.txt", "a") as mon:
                    mon.write(monitor_domain+"\n")
                print(colored("Successfully added!!!!", "green"))
                sys.exit(0)
            except IOError:
                print(colored("Warnning!:Fail to add domain!", "red"))
                sys.exit(1)
        else:
            print(colored("Warnning!:Unsupported method!!!", "red"))

    if execute:
        size_163 = os.path.getsize("mon_163.txt")
        size_qq = os.path.getsize("mon_qq.txt")
        temp_163 = {}
        temp_qq = {}
        with open("mon_163.txt", "r") as mon:
            if size_163 == 0:
                pass
            else:
                for i in mon.readlines():
                    i = i.strip("\n").strip()
                    if i:
                        old_163 = search_sub(i)
                        temp_163[i] = old_163
                        os.system("cd {} && python Beholder.py -u {} -c -r".format(path, i.strip()))
                email_prepare_163(temp_163)
        with open("mon_qq.txt", "r") as mon:
            if size_qq == 0:
                pass
            else:
                for i in mon.readlines():
                    i = i.strip("\n").strip()
                    if i:
                        old_qq = search_sub(i)
                        temp_qq[i] = old_qq
                        os.system("cd {} && python Beholder.py -u {} -c -r".format(path, i))
                email_prepare_qq(temp_qq)
        sys.exit(0)

    try:
        if redis:
            try:
                test_conn(conn)
            except:
                print(colored("Redis server seems not running! PLZ check the Redis status!", "red"))
                sys.exit(1)
            try:
                subdomain = someoper(url)
                if confirm:
                    alive = prepare_test(subdomain)
                    alive_amount = len(alive)
                    print(colored("[*]These domains below are alive!!!!!!!!", "red"))
                    print(colored("--------There are {} domains alive now---------".format(alive_amount), "red"))
                    for domain in alive:
                        print(domain)
                    export_file(False, alive, url, output)
                    saving(alive, conn, url)
                else:
                    export_file(False, subdomain, url, output)
                    saving(subdomain, conn, url)
            except Exception as e:
                print(e)
                sys.exit(1)
        else:
            if search == "" and redis is False:
                try:
                    subdomain = someoper(url) 
                    amount = len(subdomain)
                    print(colored("---------Here are the {} subdomains----------".format(amount), "green"))
                    for i in subdomain:
                        print(i)
                    print(colored("---------DONE!!!!!!!!!!!!!!!!----------", "green"))
                    if confirm:
                        alive = prepare_test(subdomain)
                        alive_amount = len(alive)
                        print(colored("[*]These domains below are alive!!!!!!!!", "red"))
                        print(colored("--------There are {} domains alive now---------".format(alive_amount), "red"))
                        for domain in alive:
                            print(domain)
                        export_file(False, domain, url, output)
                    export_file(False, subdomain, url, output)
                except Exception as e:
                    print(e)
                    sys.exit(1)
    except Exception as e:
        print(e)
