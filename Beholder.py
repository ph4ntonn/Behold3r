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


Author = "Aiden Qi(@ph4ntom)"
Version = '1.1'
Email = "ph4ntom11235@gmail.com"


def args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
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


def conn_redis():
    return Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DATABASE)


def test_conn(conn):
    conn.set("Beholder", "Beholder")
    conn.delete("Beholder")


def del_dup(data):
    data = set(data)
    return data


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


def check_given_url(url):
    try:
        TLD = get_fld(url)
        return TLD
    except Exception as e:
        print(e)
        print(colored("The format of given url is WRONG!!! It must like *.example.com(.cn,.net,etc...)", "red"))
        sys.exit(1)


def prepare_test(domains):
    global ready, domains_alive
    threads = []
    print(colored("---------Testing----------", "green"))
    for domain in domains:
        ready.put(domain)
    for i in range(THREADS):
        t = threading.Thread(target=test_alive)
        threads.append(t)
    for i in threads:
        i.start()
    for i in threads:
        i.join()
    return domains_alive


def test_alive():
    global ready, domains_alive
    while True:
        try:
            if ready.empty() is False:
                domain = ready.get()
                response = requests.get("http://{}".format(domain), timeout=timeout)
                if response.status_code == 200 or response.status_code == 443 or response.status_code == 302:
                    domains_alive.append(domain)
            else:
                return 0
        except Exception as e:
            pass


def search_sub(url, output):
    conn = conn_redis()
    try:
        length = conn.llen(url)
        results = conn.lrange(url, 0, int(length))
        print(colored("----------Found {} records!----------".format(length), "green"))
        print(colored("----------The subdomains of given url are shown as below----------", "green"))
        for i in results:
            print(i.decode('utf-8'))
        print(colored("----------That's all!!!!!!----------", "green"))
        if output:
            filename = get_tld(url,as_object=True)
            filename = filename.domain
            try:
                with open("{}.txt".format(filename), "a") as subdomain:
                   for i in results:
                        subdomain.write(i.decode('utf-8')+"\n")
                print(colored("Export sudomain file successfully, check the {}.txt!".format(filename),"green"))
            except Exception as e:
                print(colored("Cannot export subdomain as .txt file","red"))
        return list(results)
    except Exception as e:
        print(e)
        print(colored("Cannot find any data!", "red"))


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


def check_diff(old_data, new_data):
    changed_data = [i for i in new_data if i not in old_data]
    return changed_data


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


def print_status(status, source):
    if status == 'start':
        print(colored("Searching the subdomains through {}....... ".format(source), "green"))
    elif status == 'error':
        print(colored("----------{} seems down,Skipping....----------".format(source), "red"))
    else:
        pass


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
                response = self.sender.get(self.url, headers=headers, timeout=5)
            else:
                response = self.sender.post(self.url, data=param, headers=headers, timeout=5)
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
                response = self.sender.get(self.url, headers=headers, timeout=5)
            elif method == "POST":
                response = self.sender.post(self.url, headers=headers, data=param, timeout=5)
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
                TLD = check_given_url(url)
                dnsdump = Dnsdumpster(TLD)
                dnsscan = Dnsscan(TLD)
                print(colored("Some operations may take a few minutes,please wait......", "green"))
                subdomain = check_subdomain_bycrt(TLD)
                subdomain += check_subdomain_byip138(TLD)
                subdomain += dnsdump.worker()
                subdomain += dnsscan.worker()
                subdomain = del_dup(subdomain)
                if confirm:
                    alive = prepare_test(subdomain)
                    alive_amount = len(alive)
                    print(colored("[*]These domains below are alive!!!!!!!!", "red"))
                    print(colored("--------There are {} domains alive now---------".format(alive_amount), "red"))
                    for domain in alive:
                        print(domain)
                    saving(alive, conn, url)
                else:
                    saving(subdomain, conn, url)
            except Exception as e:
                print(e)
                sys.exit(1)
        else:
            if search == "" and redis is False:
                try:
                    TLD = check_given_url(url)
                    dnsdump = Dnsdumpster(TLD)
                    dnsscan = Dnsscan(TLD)
                    print(colored("Some operations may take a few minutes,please wait......", "green"))
                    subdomain = check_subdomain_bycrt(TLD)
                    subdomain += check_subdomain_byip138(TLD)
                    subdomain += dnsdump.worker()
                    subdomain += dnsscan.worker()
                    subdomain = del_dup(subdomain)
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
                except Exception as e:
                    print(e)
                    sys.exit(1)
    except Exception as e:
        print(e)
