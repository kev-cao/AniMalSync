import requests
import secrets
import os
from dotenv import load_dotenv

def get_new_code_verifier() -> str:
    return secrets.token_urlsafe(100)[:128]

load_dotenv()
client_id = os.getenv("MAL_CLIENT_ID")
client_secret = os.getenv("MAL_CLIENT_SECRET")
code_verifier = code_challenge = get_new_code_verifier()
print(code_verifier)

auth_url = f"https://myanimelist.net/v1/oauth2/authorize?response_type=code&client_id={client_id}&code_challenge={code_challenge}&state=luclid"

print(f"Click this URL to authorize: {auth_url}")

auth_code = input("Provide the auth code: ")
resp = requests.post("https://myanimelist.net/v1/oauth2/token", data={
    'client_id': client_id,
    'client_secret': client_secret,
    'code': auth_code,
    'code_verifier': code_verifier,
    'grant_type': "authorization_code"
    })

print(resp.json())
