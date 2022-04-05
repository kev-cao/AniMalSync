from utils.anilist import AnilistClient
from utils.mal import MALClient
from utils.config import config
from utils.httpexception import HTTPException
from utils.logger import logger

def main():
    anilist = AnilistClient()
    mal = MALClient()
    users = config['users'].keys()

    for user in users:
        anime_entries = anilist.fetch_recently_updated_anime(user, config['users'][user]['last_synced'])[::-1]
        for entry in anime_entries:
            try:
                mal.update_anime_list_entry(user, entry)
                config['users'][user]['last_synced'] = entry['updatedAt']
                logger.info(f"User: {user} | Synced {AnilistClient.get_anime_title(entry)}")
            except HTTPException as err:
                logger.error(f"HTTP {err.code} ERROR: {err.message}")
                if err.code == 401:
                    break

    config.save()

if __name__ == "__main__":
    main()
