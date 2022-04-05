import os
import boto3
import secrets
import time

def lambda_handler(event, context):
    """
    Sends an email notification to user with MAL OAuth link.

    Args:
        event (dict): AWS triggering event
        context (dict): AWS context

    Returns:
        (dict): JSON response to triggering event
    """
    try:
        user = event['user']
    except KeyError as e:
        print(e)
        return create_response(400, "Need to provide user to email.")

    # Fetch config file
    s3 = boto3.client('s3')
    bucket = 'anilist-to-mal-config'
    key = 'config.json'
    try:
        data = s3.get_object(Bucket=bucket, Key=key)
        config = json.loads(data['Body'].read())
    except (s3.exceptions.NoSuchKey, s3.exceptions.InvalidObjectState) as e:
        print(e)
        return create_response(500, "The server failed to fetch config.")
    except JSONDecodeError as e:
        print(e)
        return create_response(500, "The config file could not be decoded.")

    try:
        user_email = config['users'][user]['email']
    except KeyError as e:
        print(e)
        return create_response(404, "Could not find user email in config.")

    mal_id = config['MAL_CLIENT_ID']
    mal_secret = config['MAL_CLIENT_SECRET']

    # Generate and send email
    ses = boto3.client('ses', region_name=os.environ['AWS_REGION'])
    code_challenge = secrets.token_urlsafe(100)[:128]
    auth_url = f"https://myanimelist.net/v1/oauth2/authorize?response_type=code&client_id={mal_id}&code_challenge={code_challenge}&state={user}"

    try:
        ses_client.send_email(
                Destination={
                    'ToAddresses': [user_email]
                    },
                Message={
                    'Body': {
                        'Text': {
                            'Charset': 'UTF-8',
                            'Data': f"Click this link to authorize Anilist-to-MAL-sync to be able to update your MAL: {auth_url}"
                            }
                        }
                    },
                Subject={
                    'Charset': 'UTF-8',
                    'Data': "Anilist-to-MAL-Sync Authorization"
                    },
                Source='defcoding@gmail.com'
                )
    except SES.Client.exceptions.MessageRejected as e:
        print(e)
        return create_response(500, "Could not send notification email.")

    config['users'][user]['code_verifier'] = code_challenge
    config['users'][user]['last_notified'] = int(time.time())
    config['users'][user]['auth_failed'] = False
    s3.put_object(Body=json.dumps(config), Bucket=bucket, Key=key)
    return create_response(200, "Email successfully sent!")

def create_response(code: int, body: str) -> dict:
    """
    Creates a JSON response for HTTP.

    Args:
        code (int): The HTTP status code
        body (str): The HTTP body as a string

    Returns:
        (dict): JSON HTTP response
    """
    return {
            'headers': {
                'Content-Type': 'text/html'
                },
            'statusCode': code,
            'body': body
            }

