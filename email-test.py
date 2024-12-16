import boto3
import json

# Initialize the SES client
ses = boto3.client('ses', region_name='us-west-2')

# Replace with your verified sender and recipient email addresses in SES
SENDER_EMAIL = 'ewhd22+aws.ses.alerts@gmail.com'
RECIPIENT_EMAIL = 'ewhd22@gmail.com'


def lambda_handler(event, context):
    try:
        # Log the incoming event
        print("Received event:", json.dumps(event, indent=2))

        # Format the email body
        email_body = f"Lambda Function Received Data:\n\n{json.dumps(event, indent=2)}"

        # Send an email
        response = ses.send_email(
            Source=SENDER_EMAIL,
            Destination={
                'ToAddresses': [
                    RECIPIENT_EMAIL,
                ]
            },
            Message={
                'Subject': {
                    'Data': 'AWS Lambda Test: Data Received',
                },
                'Body': {
                    'Text': {
                        'Data': email_body,
                    }
                }
            }
        )

        print("Email sent successfully:", response)

        return {
            'statusCode': 200,
            'body': json.dumps('Email sent successfully!')
        }

    except Exception as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Failed to send email: {str(e)}")
        }
