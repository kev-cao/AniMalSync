import json
import time
import boto3
import os
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr
from utils.anilist import AnilistClient
from utils.aws import get_dynamodb_user, log_sync, send_mal_authorization_email, update_dynamodb_user
from utils.mal import MALClient
from utils.exception import EmailNotVerifiedException, HTTPException, AniMalUserNotFoundException, MalUnauthorizedException
from utils.logger import logger

anilist = AnilistClient()
mal = MALClient()

def lambda_handler(event, _):
    """
    Performs a sync for a user upon lambda trigger.

    Args:
        event (dict): AWS triggering event

    Returns:
        (dict): JSON response to triggering event
    """
    messages = event['Records']

    failures = [] # Messages to redo

    for msg in messages:
        msg_contents = json.loads(json.loads(msg['body'])['Message'])
        try:
            if msg_contents['type'] == 'AUTO_SYNC':
                schedule_auto_sync()
            else:
                user_id = msg_contents['user_id']
                sync_user(user_id)
        except Exception as e:
            if msg_contents['type'] == 'AUTO_SYNC':
                logger.error(f'[AUTO_SYNC] Scheduling auto sync failed: {e}')
            else:
                logger.error(f"[User {user_id}] Sync process failed: {e}")
            failures.append({
                'itemIdentifier': msg['messageId']
            })

    return {
        'batchItemFailures': failures
    }

def schedule_auto_sync():
    """
    Schedules auto-sync for every user that has it enabled.
    """
    dynamodb = boto3.resource(
        'dynamodb',
        region_name=os.environ['AWS_REGION_NAME']
    )
    user_table = dynamodb.Table(os.environ['AWS_USER_DYNAMODB_TABLE'])
    sync_users = user_table.scan(
        Select='SPECIFIC_ATTRIBUTES',
        ProjectionExpression='id',
        FilterExpression=Attr('sync_enabled').eq(True)
    )['Items']

    sns = boto3.resource('sns', region_name=os.environ['AWS_REGION_NAME'])
    sync_topic = sns.Topic(os.environ['AWS_SNS_SYNC_TOPIC'])
    # A bit slow if there were hundreds or thousands of users, but I'm not 
    # planning on having that many users. If I were to scale this up, would
    # probably do a batch publish.
    for user in sync_users:
        sync_topic.publish(Message=json.dumps({
            'type': 'USER',
            'user_id': user['id']
            }))

    # Reschedule another mass auto-sync.
    sfn = boto3.client('stepfunctions')
    # If this fails, this message should be processed again so not catching error
    sfn.start_execution(
        stateMachineArn=os.environ['AWS_SFN_ARN'],
        input=json.dumps({
            'type': 'AUTO_SYNC'
        })
    )

def sync_user(user_id):
    """
    Syncs a single user's MAL to their AniList.

    Args:
        user_id (str): The AniMalSync id of the user to sync
    """
    user = get_dynamodb_user(
        user_id=user_id,
        fields=[
            'id', 'anilist_user_id', 'email', 'sent_mal_auth_email',
            'mal_access_token', 'mal_refresh_token', 'email_verified',
            'last_sync_timestamp', 'sync_enabled'
        ]
    ) 

    # Check that user can be synced
    if user is None:
        raise AniMalUserNotFoundException(user_id)

    if not user['email_verified']:
        raise EmailNotVerifiedException(user_id)

    if 'mal_access_token' not in user or 'mal_refresh_token' not in user:
        raise MalUnauthorizedException(user_id)

    if not user['sync_enabled']: # Do not run script if user disabled sync
        return

    media_entries = anilist.fetch_recently_updated_media(
        user['anilist_user_id'], user.get('last_sync_timestamp', int(time.time()))
    )[::-1]

    # Iterate through entries and update on MAL
    for entry in media_entries:
        try:
            mal.update_media_list_entry(user, entry)
            logger.info(f"[User {user['id']}] ({entry['media']['type']}) Synced {AnilistClient.get_media_title(entry)}")
            log_sync(user, entry, True)
        except MalUnauthorizedException:
            # If the user is not authorized on MAL, cease all further updates
            # and send authorization email
            try:
                send_mal_authorization_email(user=user)
                return
            except ClientError as e:
                # If sending authorization email failed, count this message as a failed message
                logger.error(f"[User {user['id']}] Could not trigger OAuth email lambda: {e}")
                raise e
        except HTTPException as e:
            logger.error(f"[User {user['id']}] ({entry['media']['type']}) Failed to sync {AnilistClient.get_media_title(entry)}")
            log_sync(user, entry, False)

    try:
        # Update user's last sync time (assuming no mal authorization was needed)
        update_dynamodb_user(
            user_id=user_id,
            data={
                'last_sync_timestamp': int(time.time())
            }
        )
    except ClientError as e:
        logger.error(f"[User {user_id}] Failed to update user's last sync time")