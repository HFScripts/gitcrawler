import os
import socket
import ipaddress
import subprocess
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import tldextract
import warnings
warnings.filterwarnings("ignore")

CLOUDFLARE_IP_RANGES = [
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/12',
    '172.64.0.0/13',
    '131.0.72.0/22',
]

EXCLUDED_TLDS = ['.gov']
checked_domains = set()

def ensure_git_script_exists():
    if not os.path.exists("git.nse"):
        with open("git.nse", "w") as file:
            file.write(
                """local http = require "http"
portrule = function(host, port)
  return port.protocol == "tcp" and (port.number == 80 or port.number == 443)
end
action = function(host, port)
  local path = "/.git/HEAD" 
  local response = http.get(host, port, path)
  if response.status == 200 and response.body:find("ref: ") then
    print("Git repository found at " .. host.ip .. ":" .. port.number)
  end
end"""
            )


def valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def is_cloudflare_ip(ip):
    for ip_range in CLOUDFLARE_IP_RANGES:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
            return True
    return False

def is_excluded_tld(url):
    domain = tldextract.extract(url)
    return domain.suffix in EXCLUDED_TLDS

def is_valid_domain(url):
    domain = urlparse(url).netloc
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        pass
        return False
    if os.path.exists("checked.txt"):
        with open("checked.txt", "r") as file:
            if domain in (line.strip() for line in file):
                return False
    return not is_cloudflare_ip(ip) and not is_excluded_tld(url)

def extract_links(url):
    urls = set()
    domain_name = urlparse(url).netloc
    try:
        soup = BeautifulSoup(requests.get(url).content, "html.parser")
    except Exception as e:
        pass
        return urls

    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            continue

        href = urljoin(url, href)
        parsed_href = urlparse(href)
        href = parsed_href.scheme + "://" + parsed_href.netloc
        if domain_name not in href:
            if valid_url(href):
                urls.add(href)

    return urls

def check_git(url):
    domain = urlparse(url).netloc
    command = f'nmap -p 80,443 --script git.nse {domain} -oG - | grep "Git repository found at"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    output = result.stdout.strip()
    error_output = result.stderr.strip()

    if error_output:
        pass

    if "Git repository found at" in output:
        #print(url + " Git repository found. Report it immediately")
        with open("git_repos.txt", "a") as file:  # Open file in append mode
            file.write(url + "\n")  # Write the URL to the file

def strip_url_scheme_www(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

def append_checked_domain_to_file(domain):
    with open("checked.txt", "a") as file:
        file.write(domain + "\n")

def count_git_repos():
    if not os.path.exists("git_repos.txt"):
        return 0
    with open("git_repos.txt", "r") as file:
        return len(set(line.strip() for line in file))

def count_checked_domains():
    if not os.path.exists("checked.txt"):
        return 0
    with open("checked.txt", "r") as file:
        return len(set(line.strip() for line in file))

def main(url, is_starting_url=False):
    global checked_domains
    try:
        stripped_url = strip_url_scheme_www(url)
        if is_starting_url or (stripped_url not in checked_domains and is_valid_domain(url)):
            checked_domains.add(stripped_url)
            append_checked_domain_to_file(stripped_url)
            total_checked_domains = count_checked_domains()  # Get the total count
            total_git_repos = count_git_repos()  # Get the total git repositories
            print(f'\rChecked {total_checked_domains} unique domains... {total_git_repos} git repositories found.', end='')  # Print the total count
            check_git(url)
            urls = extract_links(url)
            for link in urls:
                stripped_link = strip_url_scheme_www(link)
                if stripped_link not in checked_domains:
                    main(link)
    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")
        exit()

if __name__ == "__main__":
    ensure_git_script_exists()

    try:
        if os.path.exists("checked.txt"):
            with open("checked.txt", "r") as file:
                for line in file:
                    checked_domains.add(strip_url_scheme_www(line.strip()))

        starting_url = "http://molodaja-semja.ru/"
        main(starting_url, True)
    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")
        exit()
