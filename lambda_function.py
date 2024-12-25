import boto3
import gzip
import json
import os
import requests
import time
from datetime import datetime

s3 = boto3.client('s3')
ses = boto3.client('ses')
aws_region = "us-west-2"


def read_from_s3(event, context):
    """
    Retrieves recent log data from S3 bucket.

    Parses the S3 event notification, fetches the log object, decompress it,
    and returns the contents.
    """

    # Parse S3 event notification
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    # Fetch the object from S3
    response = s3.get_object(Bucket=bucket, Key=key)
    compressed_data = response['Body'].read()

    # Decompress the .gz file
    decompressed_data = gzip.decompress(compressed_data).decode('utf-8')
    # print(type(decompressed_data))
    return decompressed_data


def ses_send_email_alert(
        subject,
        message,
        sender="ewhd22+aws.ses.alerts@gmail.com",
        receiver="ewhd22@gmail.com"
):
    """
    Sends an alert using AWS Simple Email Service
    """

    # Send the email using SES
    response = ses.send_email(
        Source=sender,
        Destination={
            'ToAddresses': [receiver]
        },
        Message={
            'Subject': {
                'Data': subject
            },
            'Body': {
                'Text': {
                    'Data': message
                }
            }
        }
    )
    # print(f"Email sent successfully! Message ID: {response['MessageId']}")


def rate_limited_api_call(
        api_arg,
        api_url='https://www.virustotal.com/api/v3/ip_addresses/',
        api_key=os.environ.get('VT_API_KEY'),
        rate_limit=4,  # per minute
        max_retries=3,
        ):
    """
    Make an API call, respecting the rate limit.
    """
    headers = {"x-apikey": api_key}
    url = f'{api_url}{api_arg}'
    # current_time = time.time()
    attempt = 0

    while attempt < max_retries:
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                time.sleep(60 / rate_limit)
                return response
            elif response.status_code == 429:
                print("Rate limit exceeded. Retrying after 60 seconds...")
                time.sleep(60)
            else:
                # Log non-200 responses for debugging
                print(f"Error {response.status_code}: {response.text}")
                return None
        except requests.exceptions.Timeout:
            print("Request timed out. Retrying...")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")


def lambda_handler(event, context):
    """
    Reads log data, checks if IPs are known unsafe, and sends an email
    alert if they are.
    """

    all_IPs = []
    malicicious_IP_data = []
    formatted_JSON_data_set = []

    # Retrieve data from S3, decompress it, process each line as a
    # separate JSON object, extract the IP, and add it to a list
    decompressed_data = read_from_s3(event, context)
    print("Data read from S3")
    try:
        for line in decompressed_data.strip().split("\n"):
            log_entry = json.loads(line)
            IP = log_entry["c-ip"]
            print(f"IP extracted from data: {IP}")
            all_IPs.append(IP)
        print("IPs extracted from S3 data")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        raise
    print(f'All IPs found: {all_IPs}')
    unique_IPs = set(all_IPs)    # Remove duplicates by converting a set
    print(f'All IPs found: {unique_IPs}')

    # Query VirusTotal API about the IP, filter the resulting JSON for
    # the analysis stats, evaluate the "malicious" score and add
    # malicious IP data to a list
    for ip in unique_IPs:
        print(f"Attempting API call on {ip}")
        response = rate_limited_api_call(ip)
        result = response.json()
        filtered_data = {
            "IP": result.get("data", {}).get("id"),
            "Last Analysis Stats": result.get("data",{}).get("attributes", {}).get("last_analysis_stats"),
        }
        malicious_score = filtered_data['Last Analysis Stats']['malicious']
        if malicious_score > 0:
            malicicious_IP_data.append(filtered_data)
    print("API calls made")

    # Form email
    timestamp = datetime.now()
    if len(malicicious_IP_data) > 0:
        # Pretty format the malicious IP JSON data
        for data in malicicious_IP_data:
            formatted_data = json.dumps(data, indent=4)
            formatted_JSON_data_set.append(formatted_data)

        # Prepare email with the prettified JSON as message body
        email_subject = "Summary of malicious IP contact"
        email_body = 'The following malicious IPs recently visited my website:\n\n'
        for data in formatted_JSON_data_set:
            email_body = f'{email_body}{data}\n'
        email_body = f'{email_body}\nReport generated at {timestamp::%Y-%m-%dT%H:%M}'
    else:
        email_subject = "No malicious IP contact"
        email_body = f'No malicious IP contact detected\n\nReport generated at {timestamp::%Y-%m-%dT%H:%M}'

    ses_send_email_alert(email_subject, email_body)
    print("Email sent")

    return {"status": "success"}
