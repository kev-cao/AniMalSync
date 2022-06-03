from __future__ import annotations
import requests
from textwrap import dedent
from utils.exception import HTTPException
from utils.logger import logger

class AnilistClient:
    """
    Anilist object that handles interactions with the Anilist GraphQL API
    """

    def __init__(self):
        self.session = requests.Session()
        self.api = "https://graphql.anilist.co/"

    def fetch_recently_updated_media(self, user_id: str, updated_after: int=0) -> list[dict]:
        """
        Fetches all recently updated media after a certain date.

        Args:
            user_id (str): The user id of the AniList user to fetch data about
            updated_after (int, optional): Epoch format. Only media that
                were updated after this timestamp should be shown

        Returns:
            [dict]: A list of MediaList entries

        Raises:
            Exception: Error with API query
        """
        curr_page = 1
        entries = []

        while True:
            entry_page = self.__fetch_recently_updated_media(user_id, updated_after, curr_page)
            if entry_page:
                entries += entry_page
                curr_page += 1
            else:
                break

        return entries

    def __fetch_recently_updated_media(self, user_id: str, updated_after: int=0, page: int=1, per_page: int=50) -> list[dict]:
        """
        Fetches all recently updated media after a certain date for a
        given user by page.

        Args:
            user_id (str): The user id of the AniList user to fetch data about
            updated_after (int, optional): Epoch format. Only media that
                were updated after this timestamp should be shown
            page (int, optional): Which page of paginated results to fetch
            per_page (int, optional): Number of entries per page

        Returns:
            [dict]: A list of MediaList entries

        Raises:
            HTTPException: Error with API query
        """
        # Fetch first entry of page to see if it is passes the updated_after filter.
        query = self.__construct_media_list_query(user_id, page)
        resp = self.__make_api_query(query)
        media = resp['data']['Page']['mediaList'][0]

        # If first entry does not pass filter, then no entries after this will.
        if media['updatedAt'] <= updated_after:
            return []

        query = self.__construct_media_list_query(user_id, page, per_page)
        resp = self.__make_api_query(query)
        mediaEntries = resp['data']['Page']['mediaList']
        return list(filter(lambda entry : entry['updatedAt'] > updated_after, mediaEntries))

    def __make_api_query(self, query: str):
        """
        Makes a GraphQL query to the AniList API with the provided query.

        Args:
            query (str): The GraphQL query

        Returns:
            dict: The HTTP response

        Raises:
            HTTPException: Error with query
        """
        resp = self.session.post(self.api, json={ 'query': query })
        resp_json = resp.json()
        if 'errors' in resp_json:
            err_msg = resp_json['errors'][0]['message']
            logger.error("Error with Anilist query: {query}\n{err_msg}")
            raise HTTPException(resp.status_code, err_msg)
        return resp_json

    @classmethod
    def __construct_media_list_query(cls, user_id: int, page: int=1, per_page: int=1) -> str:
        """
        Constructs a GraphQL query to fetch a user's media list from AniList in order of
        last update time.

        Args:
            user_id (int): The user id of the AniList user to fetch data about
            page (int, optional): Which page of paginated results to fetch
            per_page (int, optional): Number of entries per page

        Returns:
            str: The GraphQL query
        """
        return dedent(f"""\
                {{
                    Page(page: {page}, perPage: {per_page}) {{
                        mediaList(userId: {user_id}, sort: UPDATED_TIME_DESC) {{
                            media {{
                                title {{
                                    romaji
                                    english
                                    native
                                }}
                                type
                                idMal
                            }}
                            score(format: POINT_10_DECIMAL)
                            updatedAt
                            notes
                            progress
                            progressVolumes
                            status
                            repeat
                        }}
                    }}
                }}""")

    @staticmethod
    def get_media_title(entry: dict, lang: str="romaji") -> str:
        """
        Fetches an media's title from an Anilist entry.

        Args:
            entry (dict): The Anilist entry
            lang (str): The title format (romaji, english, native)

        Returns:
            (str): The media's title

        Raises:
            ValueError: Given invalid lang
        """
        if lang != 'romaji' and lang != 'english' and lang != 'native':
            raise ValueError("Invalid title lang given. Must be romaji, english, or native")
        return entry['media']['title'][lang]
