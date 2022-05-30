import boto3
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
        user = table.get_item(
            Key={ 'id' : user_id },
            ProjectionExpression=','.join(fields)
            )
        user = user['Item'] if 'Item' in user else None
    else:
        users = table.query(
            IndexName='email-index',
            Select='SPECIFIC_ATTRIBUTES',
            KeyConditionExpression=Key('email').eq(email),
            ProjectionExpression=','.join(fields)
        )['Items']
        user = users[0] if users else None

    return user
    