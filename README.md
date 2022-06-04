# AniMalSync
[![](https://img.shields.io/badge/Cloud-aws-%23ff9900?logo=amazonaws)](https://aws.amazon.com/)
[![](https://img.shields.io/badge/API-Anilist-%2300a8ff?logo=Anilist)](https://anilist.gitbook.io/anilist-apiv2-docs/)
[![](https://img.shields.io/badge/API-MAL-%232e51a2?logo=MyAnimeList)](https://myanimelist.net/apiconfig/references/api/v2)
[![](https://img.shields.io/badge/license-MIT-informational)](https://github.com/defCoding/anilist-to-mal-sync/blob/master/LICENSE)

AniMalSync is a webapp that syncs up anime/manga entries from Anilist to your MyAnimeList account.

## App Features
- Syncs following changes to AniList entries to MAL:
    - Status
    - Score
    - Progress
    - Repeating
    - Times Repeated
- Keeps track of recent sync logs on user profile
- Automatic MAL re-oauthorization email

## How the App Works
The webapp is deployed on Elastic Beanstalk to automatically handle the load balancer and target groups. DynamoDB is used to store user login information, MAL OAuth info, and other various data for the app to run correctly. When a user signs up for an account and enables automatic sync, a notification is published to a SNS topic, picked up by the subscribed SQS queue, which then triggers the a lambda which performs the AniList to MAL sync. Upon a successful sync, a SFN step function is triggered, which waits X minutes before republishing a sync to the SNS topic again, repeating the cycle. If a sync fails due to an MAL authorization issue, another lambda is triggered, which sends the authorization email to the user (the email lambda isn't really necessary though, I mostly use it to avoid code duplication for the webapp and sync lambda). Here's a flowchart to help illustrate the process:

![](/aws_flowchart.png)


## Context and Challenges
I had just recently switched over from MAL to Anilist for my anime/manga organization. However, I still wanted to keep my MAL up to date as well in case I ever decided to switch back. Fortunately, both MAL and Anilist provide an API. The idea behind this script is to run every X minutes, and take any new updates on my Anilist account and mirror those changes on MAL. Originally the script ran solely on my Raspberry Pi, but I decided to port it over to a webapp using AWS.

Prior to this project, I only had exposure to REST APIs -- however, as Anilist uses a GraphQL API, this was a perfect chance for me to learn some GraphQL. The underlying mechanism of this program was fairly straight forward. Fetch paginated results of recent activity on my Anilist account, parse that into a MAL entry, and make a PUT request on MAL's API. This mechanism was implemented fairly quickly.

However, I quickly ran into issues with user authorization. As this program would be making changes to a MAL account, I would need to use MAL's OAuth2 process to authorize my script to make changes on my account. Unfortunately, this authorization would need to be repeated once a month, when the refresh keys expire. With the basic implementation of the script, I would need to generate an authorization URL myself, authorize the script and receive an auth token, and then pass that auth token to a script that would make an authorization request to MAL.

This was way too much of a pain for me to do manually, and I needed some way of automating it. Prior to the port to the webapp, I decided to tackle this using two Lambda functions -- one to generate and send an email containing the authorization link, and another lambda with an open HTTP endpoint to fetch and store authorization keys after the MAL redirect. After porting to a webapp, it was easier to simply redirect to the MAL authorization to the webserver, and make the entire sync script a lambda instead, triggered by an SQS queue.

This was also a great opportunity for me to learn a bit more about CD. I wanted to keep all my code on this Github repo and automatically deploy the subdirectories to their respective AWS services. To do that, I learned to use GitHub actions and set up the hooks.

Overall, this was a great learning experience for me and one of the most educational projects I've done in a while.
