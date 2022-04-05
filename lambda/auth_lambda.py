import json
import boto3

def lambda_handler(event, context):
    try:
        query = event['queryStringParameters']
        user = query['state']
        auth_code = query['code']
    except KeyError:
        return create_response(400, "Missing parameters for authorization.")

    s3 = boto3.client('s3')
    bucket = 'anilist-to-mal-config'
    key = 'config.json'

    try:
        data = s3.get_object(Bucket=bucket, Key=key)
        config = json.loads(data['Body'].read())
        print(config)
    except (s3.exceptions.NoSuchKey, s3.exceptions.InvalidObjectState) as e:
        print(e)
        return create_response(500, "The server failed to fetch API keys.")
    except JSONDecodeError as e:
        print(e)

    return create_response(200, "Successfully authorized!")

def create_response(code, body):
    return {
            'statusCode': code,
            'body': json.dumps(body)
            }
