import boto3
import json

# Initialize AWS clients
s3 = boto3.client('s3')
ses = boto3.client('ses')

# Email configuration
SENDER = "ewhd22+aws.ses.alerts@gmail.com"
RECIPIENT = "ewhd22@gmail.com"
AWS_REGION = "us-west-2"


def lambda_handler(event, context):
    try:
        # Extract bucket name and object key from the event
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        object_key = event['Records'][0]['s3']['object']['key']

        # Get the JSON object from S3
        response = s3.get_object(Bucket=bucket_name, Key=object_key)
        file_content = response['Body'].read().decode('utf-8')
        json_data = json.loads(file_content)

        # Format email content
        subject = f"New JSON Log File: {object_key}"
        body_text = f"The following JSON log file was added to your S3 bucket:\n\n{json.dumps(json_data, indent=4)}"

        # Send the email using SES
        response = ses.send_email(
            Source=SENDER,
            Destination={
                'ToAddresses': [RECIPIENT]
            },
            Message={
                'Subject': {
                    'Data': subject
                },
                'Body': {
                    'Text': {
                        'Data': body_text
                    }
                }
            }
        )
        print(f"Email sent successfully! Message ID: {response['MessageId']}")

        return {
            'statusCode': 200,
            'body': f"Email sent for {object_key}"
        }

    except Exception as e:
        print(f"Error processing file {object_key}: {str(e)}")
        return {
            'statusCode': 500,
            'body': f"Error processing file {object_key}: {str(e)}"
        }
