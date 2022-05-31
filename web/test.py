import boto3

sfn = boto3.client('stepfunctions')

resp = sfn.describe_execution(executionArn='arn:aws:states:us-east-2:983398483317:execution:AniMalSync-Sync-Publish:e1ae73f0-7a3c-4fd2-adde-e362533e9beb')

print(resp)
