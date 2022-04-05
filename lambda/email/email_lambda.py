import os
import boto3

def lambda_handler(event, context):
    """
    Sends an email notification to user with MAL OAuth link.

    Args:
        event (dict): AWS triggering event
        context (dict): AWS context

    Returns:
        (dict): JSON response to triggering event
    """
    ses = boto3.client("ses", region_name=os.environ['AWS_REGION'])
    print(event)
    print(context)
