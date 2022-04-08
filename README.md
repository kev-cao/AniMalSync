# anilist-to-mal-sync
[![](https://img.shields.io/badge/Cloud-aws-%23ff9900?logo=amazonaws)](https://aws.amazon.com/)
[![](https://img.shields.io/badge/API-Anilist-%2300a8ff?logo=Anilist)](https://anilist.gitbook.io/anilist-apiv2-docs/)
[![](https://img.shields.io/badge/API-MAL-%232e51a2?logo=MyAnimeList)](https://myanimelist.net/apiconfig/references/api/v2)
[![](https://img.shields.io/badge/license-MIT-informational)](https://github.com/defCoding/anilist-to-mal-sync/blob/master/LICENSE)

Syncs up anime episodes from Anilist to your MyAnimeList account

## Context
I had just recently switched over from MAL to Anilist for my anime organization. However, I still wanted to keep my MAL up to date as well in case I ever decided to switch back. Fortunately, both MAL and Anilist provide an API. The idea behind this script is to run every X minutes, and take any new updates on my Anilist account and mirror those changes on MAL.

## Challenges
Prior to this project, I only had exposure to REST APIs -- however, as Anilist uses a GraphQL API, this was a perfect chance for me to learn some GraphQL. The underlying mechanism of this program was fairly straight forward. Fetch paginated results of recent activity on my Anilist account, parse that into a MAL entry, and make a PUT request on MAL's API. This mechanism was implemented fairly quickly.

However, I quickly ran into issues with user authorization. As this program would be making changes to a MAL account, I would need to use MAL's OAuth2 process to authorize my script to make changes on my account. Unfortunately, this authorization would need to be repeated once a month, when the refresh keys expire. With the basic implementation of the script, I would need to generate an authorization URL myself, authorize the script and receive an auth token, and then pass that auth token to a script that would make an authorization request to MAL.

This was way too much of a pain for me to go through manually. I wanted some way of automating this process. This was a perfect chance for me to learn more about AWS services. I have a lambda function that when triggered, uses AWS SES to send an email to me containing the authorization URL. When I authorize the script, I am redirected to an AWS endpoint, which triggers another lambda and passes the auth token to that lambda. That lambda then handles the retrieval of new access and refresh tokens from MAL and stores that on AWS S3. The script simply needs to fetch those keys from S3 when it needs to make a request to MAL.

This was also a great opportunity for me to learn a bit more about CD. I wanted to keep all my code on this Github repo, including the lambda functions. I learned about Github Actions, and used that to automatically deploy my lambda functions to AWS when I push to the `main` branch.

Overall, this was a great learning experience for me and one of the most educational projects I've done in a while.

## How to Setup
Unfortunately, unlike my other projects, I don't have any instructions for setting this up for yourself. It's certainly doable, but you'd have to create an AWS account and set up Lambda, S3, and SES. In general, a bit too much of a hassle.
