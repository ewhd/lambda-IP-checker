#!/usr/bin/env python3

"""
challenge433-sig-malware-detection3.py

Author: Ethan Denny
Latest Revision: 5/19/2021

Purpose:
    Scan each file and directory in a given directory path, generate an MD5
    hash, and return it. This script is designed to work on both Windows and
    Linux.
"""


import os
import json


def query_virustotalAPI(hash):
    apikey = os.getenv('API_KEY_VIRUSTOTAL')
    # Set your environment variable before proceeding. You'll need a
    # free API key from virustotal.com so get signed up there first.

    # hash = 'D41D8CD98F00B204E9800998ECF8427E' # Set your hash here.

    # This concatenates everything into a working shell statement that
    # gets passed into virustotal-search.py
    query = 'python3 virustotal-search.py -k ' + apikey + ' -m ' + hash

    return os.system(query)


def main():
    dir_to_search_within = input(
        "Enter a directory to search within: ") or "../test"

    # json_data_set = search(dir_to_search_within)

    # print(json_data_set)

    dict_data_set = json.loads(json_data_set)

    total_files_scanned = 0
    total_malware_detected = 0
    results = ""

    for file_path in dict_data_set:
        total_files_scanned += 1
        result = (str(query_virustotalAPI(
            dict_data_set[file_path]["Hash Value"]))+"\n")
        if "MALICIOUS" in result:
            total_malware_detected += 1
        results += result

    print(results)
    print(total_files_scanned)
    print(total_malware_detected)


main()
