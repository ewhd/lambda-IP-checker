#!/usr/bin/env python3

"""
Purpose:
    This script takes a IP address as input, queries VT API about the IP, and
    prepares and serves up the returning YAML data
"""

import os
import requests

apikey = os.getenv('VT_API_KEY')
ip = '24.18.229.223'  # '88.80.26.2'
url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
headers = {"x-apikey": apikey}


def main():
    """"""
    response = requests.get(url, headers=headers)
    result = response.json()
    # print(response)
    # print(type(response))
    # print(response.json())
    filtered_result = {
        "IP": result.get("data", {}).get("id"),
        "Last Analysis Stats": result.get("data",{}).get("attributes", {}).get("last_analysis_stats"),
    }
    print(filtered_result)

    print(filtered_result['Last Analysis Stats']['malicious'])

if __name__ == "__main__":
    main()
