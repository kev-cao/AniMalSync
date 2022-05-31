import json
import os
import boto3
import secrets
from json import JSONDecodeError
from botocore.exceptions import ClientError

def lambda_handler(event, _):
    """
    Sends an email notification to user with MAL OAuth link.

    Args:
        event (dict): AWS triggering event

    Returns:
        (dict): JSON response to triggering event
    """
    try:
        user_id = event['user_id']
    except KeyError as e:
        print(e)
        return create_response(400, "Need to provide user to email.")

    # Fetch MAL keys
    try:
        ssm = boto3.client('ssm', region_name=os.environ['AWS_REGION_NAME'])
        param = ssm.get_parameter(
            Name='/mal_client/keys',
            WithDecryption=True
        ) ['Parameter']['Value']
        mal_keys = json.loads(param)
        mal_id = mal_keys['MAL_CLIENT_ID']
    except (ClientError, JSONDecodeError) as e:
        msg = f"[User {user_id}] Could not fetch MAL keys."
        print(f"{msg}: {e}")
        return create_response(500, msg)

    # Fetch user data
    try:
        dynamodb = boto3.resource(
            'dynamodb',
            region_name=os.environ['AWS_REGION_NAME']
        )
        table = dynamodb.Table(os.environ['AWS_USER_DYNAMODB_TABLE'])
        user = table.get_item(
            Key={ 'id': user_id },
            ProjectionExpression="email",
        )['Item']

        if 'email' not in user:
            raise KeyError()
    except (ClientError, KeyError) as e:
        msg = f"[User {user_id}] Could not fetch user email."
        print(f"{msg}: {e}")
        return create_response(500, msg)

    # Generate and send email
    ses = boto3.client('ses', region_name=os.environ['AWS_REGION_NAME'])
    code_challenge = secrets.token_urlsafe(100)[:128]
    auth_url = f"https://myanimelist.net/v1/oauth2/authorize?response_type=code&client_id={mal_id}&code_challenge={code_challenge}&state={user_id}"
    print(f"[User {user_id}] Code Challenge: {code_challenge}")

    # Add code challenge to DynamoDB
    try:
        table.update_item(
            Key={ 'id': user_id },
            UpdateExpression="SET code_verifier = :verifier",
            ExpressionAttributeValues={
                ':verifier': code_challenge
            }
        )
    except ClientError as e:
        msg = f"[User {user_id}] Could not add code challenge to user."
        print(f"{msg}: {e}")
        return create_response(500, msg)

    # Send email
    try:
        ses.send_templated_email(
            Source=os.environ['APP_EMAIL'],
            Destination={
                'ToAddresses': [user['email']]
            },
            Template=os.environ['AUTH_EMAIL_TEMPLATE'],
            TemplateData=json.dumps({
                'url': auth_url
            })
        )
    except ses.exceptions.MessageRejected as e:
        msg = f"[User {user_id}] Could not send notification email."
        print(f"{msg}: {e}")
        return create_response(500, msg)

    # Set dynamo to show that email was sent
    try:
        table.update_item(
            Key={ 'id': user_id },
            UpdateExpression="SET sent_mal_auth_email = :sent",
            ExpressionAttributeValues={
                ':sent': True
            }
        )
    except ClientError as e:
        msg = f"[User {user_id}] Could not update user to show email was sent"
        print(f"{msg}: {e}")
        return create_response(500, msg)

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
