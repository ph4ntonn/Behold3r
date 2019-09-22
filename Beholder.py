# Just4fun,don't be so serious XD
# coding: utf-8
from tld import get_fld
from redis import Redis
from termcolor import colored
from config import *
from queue import Queue
import argparse
import requests
import sys
import re
import threading


author = "Aiden Qi(@ph4ntom)"
version = '1.0'
email = "phantom11235@gmail.com"


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
    print(colored("            Author: {}".format(author), "red"))
    print(colored("            Version: {}", "red").format(version))
    print(colored("            Email: {}", "red").format(email))


def conn_redis():
    return Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DATABASE)


def test_conn(conn):
    conn.set("Behold3r", "Behold3r")
    conn.delete("Behold3r")


def del_dup(data):
    data = set(data)
    return data


def saving(data, conn):
    try:
        try:
            print(colored("[*]Checking if data has existed.....", "green"))
            conn.delete(url)
            print(colored("[*]Data has existed,clearing.....", "red"))
            if confirm is False:
                print(colored("[*]All data have shown as below.....", "green"))
                for everyone in data:
                    print(everyone)
            for everyone in data:
                conn.lpush(url, everyone)
            print(colored("[*]Saving data successfully", "green"))
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
                if response.status_code == 200 or response.status_code == 443:
                    domains_alive.append(domain)
            else:
                return 0
        except Exception as e:
            pass


def check_subdomain_bycrt(url):
    print(colored("Searching the subdomain through crt....... ", "green"))
    search_string = "%25."+str(url)
    result = []
    try:
        response = requests.get("http://crt.sh/?Identity={}&output=json".format(search_string))
        if response.status_code == 200:
            for domain in response.json():
                result.append(domain['name_value'])
            return result
        else:
            print(colored("----------crt.sh seems down,Skipping....----------", "red"))
            return result
    except Exception as e:
        print(e)
        sys.exit(1)


def check_subdomain_byip138(url):
    print(colored("Searching the subdomain through ip138....... ", "green"))
    pattern = r'_blank">([A-Za-z0-9.]*)</a></p>'
    search_result = []
    try:
        response = requests.get("https://site.ip138.com/{}/domain.htm".format(url))
        if response.status_code == 200:
            search_result = re.findall(pattern, response.text)
            return search_result
        else:
            print(colored("----------ip138 seems down,Skipping....----------", "red"))
            return search_result
    except Exception as e:
        print(e)
        sys.exit(1)


def search_sub(url):
    conn = conn_redis()
    try:
        length = conn.llen(url)
        results = conn.lrange(url, 0, int(length))
        print(colored("----------Found {} records!----------".format(length), "green"))
        print(colored("----------The subdomains of given url are shown as below----------", "green"))
        for i in results:
            print(i.decode('utf-8'))
        print(colored("----------That's all!!!!!!----------", "green"))
    except:
        print(colored("Cannot find any data!", "red"))


if __name__ == "__main__":
    redis = args().redis
    url = args().url
    search = args().search
    conn = conn_redis()
    ready = Queue()
    domains_alive = []
    confirm = args().confirm
    timeout = int(args().timeout)

    banner()

    if (redis and search):
        print("Beholder.py: error: argument -u/--url: not allowed with argument -r/--redis")
        sys.exit(1)
    else:
        pass

    if (search):
        search_sub(search)
    else:
        pass

    try:
        if (redis):
            try:
                test_conn(conn)
            except:
                print(colored("Redis server seems not running! PLZ check the Redis status!", "red"))
                sys.exit(1)
            try:
                TLD = check_given_url(url)
                subdomain = check_subdomain_bycrt(TLD)
                subdomain += check_subdomain_byip138(TLD)
                subdomain = del_dup(subdomain)
                if confirm:
                    alive = prepare_test(subdomain)
                    alive_amount = len(alive)
                    print(colored("[*]These domains below are alive!!!!!!!!", "red"))
                    print(colored("--------There are {} domains alive now---------".format(alive_amount), "red"))
                    for domain in alive:
                        print(domain)
                    saving(alive, conn)
                else:
                    saving(subdomain, conn)
            except Exception as e:
                print(e)
                sys.exit(1)
        else:
            if (search == "" and redis is False):
                try:
                    TLD = check_given_url(url)
                    subdomain = check_subdomain_bycrt(TLD)
                    subdomain += check_subdomain_byip138(TLD)
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



