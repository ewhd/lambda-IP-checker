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
import time
import glob
import hashlib
import json

# This function takes a directory name (should handle relative or complete),
# recursively takes every file under that directory, saves a has value and
# metadata into a nested dictionary, then converts that dictionary into a json
# object and returns it


def search(dir_name):
    # First, initialize the dictionary
    results = dict()

    # Then cycle through every item under the given directory, filter for files
    for path in glob.glob(dir_name + "/**/*", recursive=True):
        if os.path.isfile(path):

            # This line finds the complete path from the relative and saves it
            file_full_path = os.path.realpath(path)

            # These lines sort out the hasvalue and metadata and save
            # them to variables (I could have bundled this all up, but
            # breaking it out like this felt clearer)

            hash_value_var = hashfile(file_full_path)
            timestamp = time.time()
            file_name = os.path.basename(file_full_path)
            file_size = os.path.getsize(file_full_path)

            # This line creates a dictionary object of
            # hashvalue+metadata for the file at this path
            dictionary = {
                "Hash Value": hash_value_var,
                "Timestamp": timestamp,
                "File Name": file_name,
                "File Size": str(file_size) + " bytes"
            }

            # This line adds the dictionary or metadata to the results
            # dicitonary, using the complete file path as a unique key
            results[file_full_path] = dictionary

    # Now that I've created this big nested dictionary, I'm going to
    # turn it into a json object and return it
    result_json = json.dumps(results, indent=4)
    return result_json


def hashfile(file_path):
    # This function takes a filepath and returns an MD5 hash value

    # make a hash object
    h = hashlib.md5()

    # open file for binary reading, then loop through 1 kb at a time,
    # updating the hash object
    with open(file_path, "rb") as file:
        chunk = 0
        while chunk != b"":
            chunk = file.read(1024)
            h.update(chunk)

    return h.hexdigest()


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

    json_data_set = search(dir_to_search_within)

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
