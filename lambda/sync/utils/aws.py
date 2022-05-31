import os
import boto3
import json
import time
import uuid
from boto3.dynamodb.conditions import Key
from utils.anilist import AnilistClient
from utils.logger import logger

dynamodb = boto3.resource(
    'dynamodb',
    region_name=os.environ['AWS_REGION_NAME']
)
user_table = dynamodb.Table(os.environ['AWS_USER_DYNAMODB_TABLE'])
log_table = dynamodb.Table(os.environ['AWS_SYNC_LOG_DYNAMODB_TABLE'])

def get_dynamodb_user(*, user_id: str=None,
                      email: str=None, fields: list[str]=[]):
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

    if user_id is not None:  
        args = { 'Key': { 'id': user_id } }
        if projection := ','.join(fields):
            args['ProjectionExpression'] = projection

        user = user_table.get_item(**args)
        user = user['Item'] if 'Item' in user else None
    else:
        args = {
            'IndexName': 'email-index',
            'Select': 'SPECIFIC_ATTRIBUTES',
            'KeyConditionExpression': Key('email').eq(email)
        }
        if projection := ','.join(fields):
            args['ProjectionExpression'] = projection

        users = user_table.query(**args)['Items']
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

    to_update = list(filter(lambda kv: kv[1] is not None, data.items()))
    to_remove = list(filter(lambda kv: kv[1] is None, data.items()))

    query = []
    if to_update:
        query.append(f"SET {','.join(map(lambda kv: f'{kv[0]} = :{kv[0]}', to_update))}")
        attr_values = { f':{kv[0]}': kv[1] for kv in to_update }
    if to_remove:
        query.append(f"REMOVE {','.join(map(lambda kv: kv[0], to_remove))}")

    args = {
        'Key':{ 'id': user['id'] },
        'UpdateExpression': ' '.join(query),
    }
    if to_update:
        args['ExpressionAttributeValues'] = attr_values

    user_table.update_item(**args)

def send_mal_authorization_email(*, user: dict, force: bool=False):
    """
    Sends a MAL authorization email to the given AniMalSync user.

    Args:
        user (dict): AniMalSync user
        force (bool): Force sending the email, even if one has been sent already

    Raises:
        (ClientError): Error occurred on AWS and could not trigger email lambda
    """
    if force or not user.get('sent_mal_auth_email', False):
        lambda_client = boto3.client('lambda', region_name=os.environ['AWS_REGION_NAME'])
        resp = lambda_client.invoke(
            FunctionName='MAL-OAuth-Emailer',
            Payload=json.dumps({
                'user_id': user['id']
            })
        )
        if resp.ok:
            logger.info(f"[User {user['id']}] Successfully triggered email lambda.")
        else:
            logger.warning(f"[User {user['id']}] Failed to trigger email lambda.")

def log_sync(user: dict, entry: dict, success: bool):
    """
    Adds a sync log to the DynamoDB table.

    Args:
        user (dict): Associated AniMalSync user
        entry (dict): AniList media entry
        success (bool): Whether the sync was a success
    """
    now = int(time.time())
    expired = now + 7 * 24 * 60 * 60 # Log removed in a week
    log = {
        'id': str(uuid.uuid4()),
        'user_id': user['id'],
        'success': success,
        'media_type': entry['media']['type'],
        'title': AnilistClient.get_media_title(entry),
        'status': entry['status'],
        'progress': entry['progress'],
        'score': str(entry['score']),
        'timestamp': now,
        'expiration_timestamp': expired
    }

    log_table.put_item(Item=log)