#!/usr/bin/env python3

"""
Purpose:
    This script takes a IP address as input, queries VT API about the IP, and
    prepares and serves up the returning YAML data
"""

import os
import requests

apikey = os.getenv('VT_API_KEY')
ip = '88.80.26.2'
url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
headers = {"x-apikey": apikey}

def main():
    """"""
    response = requests.get(url, headers=headers)
    print(response)
    print(type(response))
    print(response.json())


if __name__ == "__main__":
    main()
