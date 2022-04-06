import requests
import datetime
from textwrap import dedent
from utils.httpexception import HTTPException
from utils.logger import logger

class AnilistClient:
    """
    Anilist object that handles interactions with the Anilist GraphQL API
    """

    def __init__(self):
        self.session = requests.Session()
        self.api = "https://graphql.anilist.co/"

    def fetch_recently_updated_anime(self, username: str, updated_after: int=0) -> [dict]:
        """
        Fetches all recently updated anime after a certain date.

        Args:
            username (str): The username of the user to fetch data about
            updated_after (int, optional): Epoch format. Only anime that
                were updated after this timestamp should be shown

        Returns:
            [dict]: A list of ANIME type MediaList entries

        Raises:
            Exception: Error with API query
        """
        curr_page = 1
        entries = []

        while True:
            entry_page = self.__fetch_recently_updated_anime(username, updated_after, curr_page)
            if entry_page:
                entries += entry_page
                curr_page += 1
            else:
                break

        return entries

    def __fetch_recently_updated_anime(self, username: str, updated_after: int=0, page: int=1, per_page: int=50) -> [dict]:
        """
        Fetches all recently updated anime after a certain date for a
        given user by page.

        Args:
            username (str): The username of the user to fetch data about
            updated_after (int, optional): Epoch format. Only anime that
                were updated after this timestamp should be shown
            page (int, optional): Which page of paginated results to fetch
            per_page (int, optional): Number of entries per page

        Returns:
            [dict]: A list of ANIME type MediaList entries

        Raises:
            HTTPException: Error with API query
        """
        # Fetch first entry of page to see if it is passes the updated_after filter.
        query = self.__construct_anime_list_query(username, page)
        resp = self.__make_api_query(query)
        animeEntry = resp['data']['Page']['mediaList'][0]

        # If first entry does not pass filter, then no entries after this will.
        if animeEntry['updatedAt'] <= updated_after:
            return []

        query = self.__construct_anime_list_query(username, page, per_page)
        resp = self.__make_api_query(query)
        animeEntries = resp['data']['Page']['mediaList']
        return list(filter(lambda entry : entry['updatedAt'] > updated_after, animeEntries))

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
    def __construct_anime_list_query(cls, username: str, page: int=1, per_page: int=1) -> str:
        """
        Constructs a GraphQL query to fetch a user's anime list from AniList in order of
        last update time.

        Args:
            username (str): The username of the user to fetch data about
            page (int, optional): Which page of paginated results to fetch
            per_page (int, optional): Number of entries per page

        Returns:
            str: The GraphQL query
        """
        return dedent(f"""\
                {{
                    Page(page: {page}, perPage: {per_page}) {{
                        mediaList(userName: "{username}", sort: UPDATED_TIME_DESC, type: ANIME) {{
                            media {{
                                title {{
                                    romaji
                                    english
                                    native
                                }}
                                idMal
                            }}
                            score(format: POINT_10_DECIMAL)
                            updatedAt
                            progress
                            status
                            repeat
                        }}
                    }}
                }}""")

    @staticmethod
    def get_anime_title(entry: dict, lang: str="romaji") -> str:
        """
        Fetches an anime's title from an Anilist entry.

        Args:
            entry (dict): The Anilist entry
            lang (str): The title format (romaji, english, native)

        Returns:
            (str): The anime's title

        Raises:
            ValueError: Given invalid lang
        """
        if lang != 'romaji' and lang != 'english' and lang != 'native':
            raise ValueError("Invalid title lang given. Must be romaji, english, or native")
        return entry['media']['title'][lang]
