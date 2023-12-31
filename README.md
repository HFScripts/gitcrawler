# GitHub Crawler

This is a Python script that crawls websites in search of GitHub repositories, Once it validates and verifies them based on certain criteria, extracts all URLs from the crawled websites, and checks for the existence of Git repositories on the servers of these newly extracted URLs. 

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)

## Features

- Crawls websites to extract all URLs.
- Checks and validates URLs against predefined conditions.
- Checks if the server IPs belong to Cloudflare.
- Excludes certain top-level domains from checks.
- Executes a git script to verify if a Git repository exists on the servers of the URLs.
- Keeps track of all checked domains and identified Git repositories.
- Handles user interruptions gracefully.

## Requirements

- Python 3.6 or higher
- BeautifulSoup library for parsing HTML and XML documents
- requests library for HTTP requests
- urllib library for parsing URLs
- ipaddress library for creating, manipulating and analyzing IPv4 and IPv6 addresses and networks
- tldextract library for accurately separating the gTLD or ccTLD (generic or country code top-level domain) from the registered domain and subdomains of a URL
- nmap network scanner tool

## Installation

Clone this repository and install the required Python packages using pip:

```bash
git clone https://github.com/HFScripts/gitcrawler.git
cd gitcrawler
pip install -r requirements.txt
```

Outside of that you will need to make sure you have nmap
sudo apt-get install nmap

## Usage
```python3 gitcrawler.py```
