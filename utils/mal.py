import requests
import urllib
import os
from dotenv import load_dotenv
from typing import Optional
from utils.config import user_config
from utils.logger import logger
from utils.httpexception import HTTPException
from utils.anilist import AnilistClient

class MALClient:
    """
    MyAnimeList object that handles interactions with the MAL API.
    """

    def __init__(self):
        load_dotenv()
        self.session = requests.Session()
        self.api = "https://api.myanimelist.net/v2"
        self.client_id = os.getenv("MAL_CLIENT_ID")
        self.client_secret = os.getenv("MAL_CLIENT_SECRET")

    def update_anime_list_entry(self, user: str, entry: dict):
        """
        Updates MAL anime list with an Anilist anime entry for a given user.

        Args:
            user (str): Username of Anilist user to update entry for
            entry (dict): The Anilist entry returned by AnilistClient

        Raises:
            (HTTPException): Update failed.
        """
        anime_id = entry['media']['idMal']

        ######
        # Anilist tags their anime entries with the MAL id, so this is no longer needed for now.
        #####
        # title_types = ['native', 'romaji', 'english'] # Native titles seem to have the least ambiguity
        # for title_type in title_types:
            # if title := AnilistClient.get_anime_title(entry, title_type):
                # anime_id = self.get_anime_id(title)
                # if anime_id is not None:
                    # break
# 
        # if anime_id is None:
            # return False

        url = f"{self.api}/anime/{anime_id}/my_list_status"
        access_code = user_config[user]['mal_access_token']
        mal_entry = self.__convert_anilist_to_mal(entry)
        access_code_failed = False

        while True:
            try:
                self.session.headers.update({
                    'Authorization': f"Bearer {access_code}"
                })
                self.__process_response(self.session.patch(url, data=mal_entry))
                return
            except HTTPException as err:
                if err.code != 401:
                    logger.error(f"Error updating MAL entry for {AnilistClient.get_anime_title(entry)}: {err.message}")
                    raise err

                # If access code fails twice, there is an issue.
                if access_code_failed:
                    logger.error(f"MAL access code for {user} failed after refresh.")
                    raise err

                access_code_failed = True
                try:
                    access_code = self.refresh_user_access(user)
                except:
                    logger.error(f"MAL access code for {user} could not be refreshed. Need to reauth.")
                    raise err

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
        self.session.headers.update({ 'X-MAL-CLIENT-ID': self.client_id })
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

    def refresh_user_access(self, user: str) -> str:
        """
        Refreshes the MAL access code for the given Anilist username.

        Args:
            user (str): The Anilist username

        Returns:
            (str): The new access code for that user
        """
        refresh_token = user_config[user]['mal_refresh_token']
        url = "https://myanimelist.net/v1/oauth2/token"
        resp = self.session.post(url, data={
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        })
        data = self.__process_response(resp)
        user_config[user]['mal_access_token'] = data['access_token']
        user_config[user]['mal_refresh_token'] = data['refresh_token']
        user_config.save()
        return data['access_token']
   
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
                    f"{resp_json['error']}: {resp_json['message']}"
                    )
        return resp_json
    
    def __convert_anilist_to_mal(self, entry: dict) -> dict:
        """
        Converts an Anilist entry into a MAL entry to update MAL list.

        Args:
            entry (dict): The Anilist entry to convert

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
                'is_rewatching': entry['repeat'] > 0 and status == 'watching',
                'score': round(entry['score']),
                'num_watched_episodes': entry['progress'],
                'num_times_rewatched': entry['repeat']
                }
