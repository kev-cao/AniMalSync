import boto3
import requests
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from app import app
from flask import request, url_for, redirect
from urllib.parse import urlparse, urljoin

def is_safe_url(target):
    """
    Checks that the target url matches the original site url.

    Args:
        target (str): The desired target URL

    Returns:
        (bool): True if the target matches the site url, False otherwise
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def get_redirect_target():
    """
    Fetches the redirect target from a request.

    Returns:
        (str|None): The redirect target if it exists, otherwise false
    """
    for target in request.values.get('next'), request.args.get('next'):
        if not target:
            continue
        elif is_safe_url(target):
            return target

def redirect_back(*, fallback, **args):
    """
    Redirects to the target URL in the request if it is safe, otherwise
    redirects to a fallback.

    Args:
        fallback (str): Fallback endpoint in case request URL is not safe
        args (dict): Query params for fallback endpoint
    """
    target = request.form['next'] if request.form \
        and 'next' in request.form else request.args.get('next')
    if not target or not is_safe_url(target):
        target = url_for(fallback, **args)

    return redirect(target)

def get_dynamodb_user(*, user_id=None, email=None, fields=[]):
    """
    Fetches a user from DynamoDB either by id or by email.

    Args:
        user_id (str): The user ID of the user
        email (str): The email of the user
        fields ([str]): List of fields to fetch from dynamo. Defaults to all fields.

    Returns:
        (dict): DynamoDB user if exists, None otherwise
    
    Raises:
        ValueError: Neither user_id or email were provided
        ClientError: Error with DynamoDB resource
    """
    if user_id is None and email is None:
        raise ValueError("Must provide either an id or email.") 

    dynamodb = boto3.resource(
        'dynamodb',
        region_name=app.config['AWS_REGION_NAME']
    )
    table = dynamodb.Table(app.config['AWS_USER_DYNAMODB_TABLE'])

    if user_id is not None:  
        args = { 'Key': { 'id': user_id } }
        if projection := ','.join(fields):
            args['ProjectionExpression'] = projection

        user = table.get_item(**args)
        user = user['Item'] if 'Item' in user else None
    else:
        args = {
            'IndexName': 'email-index',
            'Select': 'SPECIFIC_ATTRIBUTES',
            'KeyConditionExpression': Key('email').eq(email)
        }
        if projection := ','.join(fields):
            args['ProjectionExpression'] = projection

        users = table.query(**args)['Items']
        user = users[0] if users else None

    return user


def update_dynamodb_user(*, user_id: str, data: dict):
    """
    Updates an AniMalSync user with new data.

    Args:
        user_id (str): The user ID of the user
        data (dict): The new fields to update

    Raises:
        (ClientError): Update failed
    """
    user = get_dynamodb_user(user_id=user_id)

    # Don't perform update if user does not exist
    if user is None:
        return

    dynamodb = boto3.resource(
        'dynamodb',
        region_name=app.config['AWS_REGION_NAME']
    )
    table = dynamodb.Table(app.config['AWS_USER_DYNAMODB_TABLE'])

    update_expr = f"SET {','.join(map(lambda k: f'{k} = :{k}', data.keys()))}"
    attr_values = { f':{k}': v for k, v in data.items() }
    table.update_item(
        Key={ 'id': user['id'] },
        UpdateExpression=update_expr,
        ExpressionAttributeValues=attr_values
    )

def get_anilist_username(user_id):
    """
    Fetches the username associated with AniList user id.

    Args:
        user_id (int): The AniList user id

    Returns:
        (str): The AniList username, or None if does not exist
    """
    query = f"""\
        {{
            User(id: {user_id}) {{
                name
            }}
        }}
        """
    resp = requests.post(
        "https://graphql.anilist.co",
        json={'query': query}
        )

    if not resp.ok:
        app.logger.error(
            f"Could not find AniList user with id {user_id}: {resp}"
        )
        return None

    try:
        return resp.json()['data']['User']['name']
    except KeyError as e:
        app.logger.error(f"Malformed response from AniList API: {e}")
        return None

def mal_is_authorized(user):
    """
    Checks if the given user's MAL account is authorized.

    Args:
        user (obj): Flask-Login user object

    Returns:
        (bool): True if MAL is authorized, False otherwise.
    """
    mal_tokens = get_dynamodb_user(
        user_id=user.id,
        fields=['mal_access_token', 'mal_refresh_token']
    )

    if 'mal_access_token' not in mal_tokens:
        return False

    # Test MAL tokens
    endpoint = "https://api.myanimelist.net/v2/users/@me"
    resp = requests.get(endpoint, headers={
        'Authorization': f"Bearer {mal_tokens['mal_access_token']}"
    })

    if not resp.ok:
        # If error code is not authorization issue, then not authorized
        if resp.status_code != 401:
            return False

        # Attempt to refresh using refresh token
        refresh_url = "https://myanimelist.net/v1/oauth2/token"
        app.logger.debug(f"Refreshing MAL token for user {user.email}.")
        resp = requests.post(
            refresh_url,
            data={
                'client_id': app.config['MAL_CLIENT_ID'],
                'client_secret': app.config['MAL_CLIENT_SECRET'],
                'grant_type': 'refresh_token',
                'refresh_token': mal_tokens['mal_refresh_token']
            }
        )

        # If refresh succeeded, update Dynamo with new tokens
        if resp.ok:
            app.logger.debug(f"Successfully refreshed MAL token for {user.email}.")
            new_tokens = resp.json()
            try:
                update_dynamodb_user(
                    user.id,
                    {
                        'mal_access_token': new_tokens['access_token'],
                        'mal_refresh_token': new_tokens['refresh_token']
                    }
                )
            except ClientError as e:
                app.logger.error(
                    ("Failed to update DynamoDB with new MAL tokens "
                     f"for user {user.email}: {e}")
                )
                return False

    return resp.ok
            