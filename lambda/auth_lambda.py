import json
import boto3
import secrets
import requests

def lambda_handler(event, context):
    """
    Updates user MAL access token and refresher on S3 bucket upon
    lambda API query.

    Args:
        event (dict): AWS triggering event
        context (dict): AWS context

    Returns:
        (dict): JSON response to triggering event
    """
    # Fetch username and auth code.
    try:
        query = event['queryStringParameters']
        user = query['state']
        auth_code = query['code']
    except KeyError:
        return create_response(400, "Missing parameters for authorization.")

    # Fetch config file from S3 bucket
    s3 = boto3.client('s3')
    bucket = 'anilist-to-mal-config'
    key = 'config.json'
    try:
        data = s3.get_object(Bucket=bucket, Key=key)
        config = json.loads(data['Body'].read())
    except (s3.exceptions.NoSuchKey, s3.exceptions.InvalidObjectState) as e:
        print(e)
        return create_response(500, "The server failed to fetch API keys.")
    except JSONDecodeError as e:
        print(e)
        return create_response(500, "The config file could not be decoded.")

    # Perform MAL OAuth
    mal_id = config['MAL_CLIENT_ID']
    mal_secret = config['MAL_CLIENT_SECRET']
    code_verifier = config['users'][user]['code_verifier']
    resp = requests.post("https://myanimelist.net/v1/oauth2/token", data={
        'client_id': mal_id,
        'client_secret': mal_secret,
        'code': auth_code,
        'code_verifier': code_verifier,
        'grant_type': "authorization_code"
        }).json()

    if 'error' in resp:
        # Record failed authorization attempt in config
        config['users'][user]['auth_failed'] = True
        s3.put_object(Body=json.dumps(config), Bucket=bucket, Key=key)
        return create_response(401,
                ("Error with authorizing user.\nDetails:\n"
                    f"Error: {resp['error']}\n"
                    f"Message: {resp['message']}\n"
                    f"Hint: {resp['hint']}"))

    config['users'][user]['mal_access_token'] = resp['access_token']
    config['users'][user]['mal_refresh_token'] = resp['refresh_token']
    config['users'][user]['auth_failed'] = False
    s3.put_object(Body=json.dumps(config), Bucket=bucket, Key=key)
    return create_response(200, "Successfully authorized!")

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
            'statusCode': code,
            'body': json.dumps(body)
            }

