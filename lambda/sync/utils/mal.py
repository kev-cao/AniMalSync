import requests
import urllib
import boto3
import os
import json
from typing import Optional
from botocore.exceptions import ClientError
from json import JSONDecodeError
from utils.logger import logger
from utils.exception import HTTPException, MalUnauthorizedException
from utils.anilist import AnilistClient
from utils.aws import update_dynamodb_user

class MALClient:
    """
    MyAnimeList object that handles interactions with the MAL API.
    """

    def __init__(self):
        self.session = requests.Session()
        self.api = "https://api.myanimelist.net/v2"
        self.client_id, self.client_secret = self.fetch_mal_keys()

    def update_media_list_entry(self, user: dict, entry: dict):
        """
        Updates MAL media list with an Anilist media entry for a given user.

        Args:
            user (dict): AniMalSync user
            entry (dict): The Anilist entry returned by AnilistClient

        Raises:
            (HTTPException): Update failed.
            (MalUnauthorizedException): User has not authorized AniMalSync to use MAL
        """
        media_id = entry['media']['idMal']
        media_type = entry['media']['type']
        access_token, refresh_token = user['mal_access_token'], user['mal_refresh_token']

        url = f"{self.api}/{media_type.lower()}/{media_id}/my_list_status"
        mal_entry = self.__convert_anilist_to_mal(entry)
        access_token_failed = False

        while True:
            try:
                self.session.headers.update({
                    'Authorization': f"Bearer {access_token}"
                })
                self.__process_response(
                    self.session.patch(url, data=mal_entry)
                )
                return
            except HTTPException as err:
                if err.code != 401:
                    logger.error(
                        (f"[User {user['id']}] Error updating MAL {media_type} entry for "
                         f"{AnilistClient.get_media_title(entry)}: {err.message}")
                    )
                    raise err

                # If access code fails twice, there is an issue.
                if access_token_failed:
                    logger.error(
                        f"[User {user['id']}] MAL access code failed after refresh"
                    )
                    raise MalUnauthorizedException(user['id'])

                access_token_failed = True
                try:
                    user['mal_access_token'] = access_token = self.refresh_mal_access(user, refresh_token)
                    logger.info(f"[User {user['id']}] Refreshed access token using refresh token")
                except HTTPException as e:
                    logger.warning(f"[User {user['id']}] Must reauthorize user: {e}")
                    raise MalUnauthorizedException(user['id'])

    def get_anime_id(self, title: str) -> Optional[int]:
        """
        (DEPRECATED: Anilist pairs anime with MAL ID)
        Searches MAL for the ID of an anime with the given title. Returns the
        top match.

        Args:
            title (str): The title of the anime to search for

        Returns:
            (Optional[int]): The anime ID, or None if no matches
        """
        self.session.headers.update({'X-MAL-CLIENT-ID': self.client_id})
        url_title = urllib.parse.quote_plus(title)
        url = f"{self.api}/anime?q={url_title}&limit=1"
        try:
            resp = self.__process_response(self.session.get(url))
        except HTTPException:
            logger.warning(f"Error fetching anime using title {url_title}")
            return None

        if len(resp['data']):
            return resp['data'][0]['node']['id']
        else:
            return None

    def refresh_mal_access(self, user: dict, refresh_token: str) -> str:
        """
        Refreshes the MAL access token with the given refresh token.

        Args:
            user (dict): AniMalSync user
            refresh_token (str): The MAL refresh token to use for refreshing

        Returns:
            (str): The new access token
        """
        url = "https://myanimelist.net/v1/oauth2/token"
        resp = self.session.post(url, data={
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        })
        data = self.__process_response(resp)

        # Save user tokens
        try:
            update_dynamodb_user(
                user_id=user['id'],
                data={
                    'mal_access_token': data['access_token'],
                    'mal_refresh_token': data['refresh_token']
                }
            )
        except ClientError as e:
            logger.error(f"[User {user['id']}] Could not save user's MAL tokens: {e}")

        return data['access_token']

    @classmethod
    def fetch_mal_keys(cls):
        """
        Fetches the MyAnimeList keys from AWS SSM.

        Raises:
            (ClientError, JSONDecodeError, KeyError): unable to fetch keys
        """
        ssm = boto3.client('ssm', region_name=os.environ['AWS_REGION_NAME'])
        # Fetch MAL keys
        try:
            param = ssm.get_parameter(
                Name='/mal_client/keys',
                WithDecryption=True
            )['Parameter']['Value']
            mal_keys = json.loads(param)
            return mal_keys['MAL_CLIENT_ID'], mal_keys['MAL_CLIENT_SECRET']
        except ClientError as e:
            logger.error(f"Unable to retrieve MAL secrets from SSM: {e}")
            raise e
        except (JSONDecodeError, KeyError) as e:
            logger.error(f"Malformed parameter value in SSM: {e}")
            raise e

    @classmethod
    def __process_response(cls, resp):
        """
        Processes an HTTP response and returns it as a dictionary object.

        Args:
            resp (obj): The HTTP response

        Returns:
            (dict): The HTTP response as a Python dict.

        Raises:
            Exception: The HTTP response came back as an error.
        """
        resp_json = resp.json()
        if 'error' in resp_json:
            raise HTTPException(
                resp.status_code,
                f"{resp_json['error']}: {resp_json.get('message')}"
            )
        return resp_json

    def __convert_anilist_to_mal(self, entry: dict) -> dict:
        """
        Converts an Anilist media entry into a MAL entry to update MAL list.

        Args:
            entry (dict): The Anilist entry to convert

        Returns:
            (dict): The MAL entry translation
        """
        if entry['media']['type'] == 'ANIME':
            mal_entry = self.__convert_anilist_anime_to_mal(entry)
        else:
            mal_entry = self.__convert_anilist_manga_to_mal(entry)

        if entry['notes']:
            mal_entry['comments'] = entry['notes']

        return mal_entry

    def __convert_anilist_anime_to_mal(self, entry: dict) -> dict:
        """
        Converts an Anilist anime entry into a MAL anime entry to update MAL list.

        Args:
            entry (dict): The Anilist anime entry to convert

        Returns:
            (dict): The MAL entry translation
        """
        status_conversion = {
            'CURRENT': 'watching',
            'PLANNING': 'plan_to_watch',
            'COMPLETED': 'completed',
            'DROPPED': 'dropped',
            'PAUSED': 'on_hold',
            'REPEATING': 'watching'
        }
        status = status_conversion[entry['status']]
        return {
            'status': status,
            'is_rewatching': 1 if entry['repeat'] > 0 and status == 'watching' else 0,
            'score': round(entry['score']),
            'num_watched_episodes': entry['progress'],
            'num_times_rewatched': entry['repeat']
        }

    def __convert_anilist_manga_to_mal(self, entry: dict) -> dict:
        """
        Converts an Anilist manga entry into a MAL manga entry to update MAL list.

        Args:
            entry (dict): The Anilist manga entry to convert

        Returns:
            (dict): The MAL entry translation
        """
        status_conversion = {
            'CURRENT': 'reading',
            'PLANNING': 'plan_to_read',
            'COMPLETED': 'completed',
            'DROPPED': 'dropped',
            'PAUSED': 'on_hold',
            'REPEATING': 'reading'
        }
        status = status_conversion[entry['status']]
        return {
            'status': status,
            'is_rereading': 1 if entry['repeat'] > 0 and status == 'reading' else 0,
            'score': round(entry['score']),
            'num_volumes_read': entry['progressVolumes'],
            'num_chapters_read': entry['progress'],
            'num_times_reread': entry['repeat']
        }
