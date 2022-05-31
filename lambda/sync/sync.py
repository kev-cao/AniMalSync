import json
import time
import boto3
import os
from botocore.exceptions import ClientError
from utils.anilist import AnilistClient
from utils.aws import get_dynamodb_user, log_sync, send_mal_authorization_email, update_dynamodb_user
from utils.mal import MALClient
from utils.exception import EmailNotVerifiedException, HTTPException, AniMalUserNotFoundException, MalUnauthorizedException
from utils.logger import logger

def lambda_handler(event, _):
    """
    Performs a sync for a user upon lambda trigger.

    Args:
        event (dict): AWS triggering event

    Returns:
        (dict): JSON response to triggering event
    """
    messages = event['Records']

    anilist = AnilistClient()
    mal = MALClient()
    sfn = boto3.client('stepfunctions')

    failures = [] # Messages to redo

    for msg in messages:
        user_id = json.loads(msg['body'])['user_id']
        try:
            user = get_dynamodb_user(
                user_id=user_id,
                fields=[
                    'id', 'anilist_user_id', 'email', 'sent_mal_auth_email',
                    'mal_access_token', 'mal_refresh_token', 'email_verified',
                    'last_sync_timestamp'
                ]
            ) 

            # Check that user can be synced
            if user is None:
                raise AniMalUserNotFoundException(user_id)

            if not user['email_verified']:
                raise EmailNotVerifiedException(user_id)

            if 'mal_access_token' not in user or 'mal_refresh_token' not in user:
                raise MalUnauthorizedException(user_id)

            media_entries = anilist.fetch_recently_updated_media(
                user['anilist_user_id'], user.get('last_sync_timestamp', 1653902100)
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

            # Schedule another sync (if this fails, this message should be processed again)
            sfn.start_execution(
                stateMachineArn=os.environ['AWS_SFN_ARN'],
                input=json.dumps({
                    'user_id': user_id
                })
            )
        except Exception as e:
            logger.error(f"[User {user_id}] Sync process failed: {e}")
            failures.append({
                'itemIdentifier': msg['messageId']
            })

    return {
        'batchItemFailures': failures
    }

# lambda_handler({
    #'Records': [
        # {
            # "body": '{ "user_id": "5ef51c97-e58e-46ab-8c2e-96a9668e2b95", "last_sync_timestamp": 1653902144 }'
        # }
    # ]
# }, None)