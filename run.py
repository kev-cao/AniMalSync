from utils.anilist import AnilistClient
from utils.mal import MALClient
from utils.cache import user_cache
from utils.httpexception import HTTPException
from utils.logger import logger

def main():
    anilist = AnilistClient()
    mal = MALClient()
    users = user_cache.keys()

    for user in users:
        media_entries = anilist.fetch_recently_updated_media(user, user_cache[user]['last_synced'])[::-1]
        for entry in media_entries:
            try:
                mal.update_media_list_entry(user, entry)
                user_cache[user]['last_synced'] = entry['updatedAt']
                logger.info(f"User: {user} | [{entry['media']['type']}] Synced {AnilistClient.get_media_title(entry)}")
            except HTTPException as err:
                logger.error(f"HTTP {err.code} ERROR: {err.message}")
                if err.code == 401:
                    break

    user_cache.save()

if __name__ == "__main__":
    main()
