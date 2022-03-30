from utils.anilist import AnilistClient
from utils.mal import MALClient
from utils.config import user_config

def main():
    anilist = AnilistClient()
    mal = MALClient()
    users = user_config.keys()

    for user in users:
        anime_entries = anilist.fetch_recently_updated_anime(user, user_config[user]['last_synced'])[::-1]
        for entry in anime_entries:
            if mal.update_anime_list_entry(user, entry):
                user_config[user]['last_synced'] = entry['updatedAt']
            else:
                print(f"Failed to update anime {entry['media']['title']['romaji']}")

    user_config.save()

if __name__ == "__main__":
    main()
