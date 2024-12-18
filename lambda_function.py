import boto3
import gzip
import json
import os
import requests
import time

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

    return decompressed_data


def ses_send_email_alert(
        message,
        subject,
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
        api_call,
        rate_limit=4,  # per minute
        max_retries=3,
        api_key=os.environ.get('VT_API_KEY'),
        api_url='https://www.virustotal.com/api/v3/ip_addresses/',
        ):
    """
    Make an API call, respecting the rate limit.
    """
    headers = {"x-apikey": api_key}
    url = api_url + api_call
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
    Reads log data, checks if IPs are known unsafe, and sends an email alert if they are.
    """

    all_IPs = []
    malicious_IPs = []

    decompressed_data = read_from_s3(event, context)

    # Process each line as a separate JSON object
    try:
        for line in decompressed_data.strip().split("\n"):
            log_entry = json.loads(line)
            # print("IP Address:", log_entry["c-ip"])
            all_IPs.append(log_entry["c-ip"])
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        raise

    for ip in all_IPs:
        response = rate_limited_api_call(ip)
        result = response.json()
        filtered_result = {
            "IP": result.get("data", {}).get("id"),
            "Last Analysis Stats": result.get("data",{}).get("attributes", {}).get("last_analysis_stats"),
        }
        malicious_score = filtered_result['Last Analysis Stats']['malicious']
        if malicious_score > 0:
            malicious_IPs.append(filtered_result['IP'])

    for ip in malicious_IPs:
        print(ip)

    return {"status": "success"}
