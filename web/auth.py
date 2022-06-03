# auth.py
# Sets up authorization and functions for Flask-Login
###

import bcrypt
from app import app
from botocore.exceptions import ClientError
from flask_login import LoginManager, UserMixin
from flask_wtf.csrf import CSRFProtect
from utils import get_dynamodb_user

# Setup anti-CSRF protection for WTForms
csrf = CSRFProtect()
csrf.init_app(app)

# Set up login manager
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    """
    Represents a logged in user for LoginManager
    """
    def __init__(self, db_user): 
        """
        Args:
            db_user (dict): A user loaded from DynamoDB
        """
        self.id = db_user['id']
        self.email = db_user['email']
        self.anilist_user_id = db_user['anilist_user_id']
        self.sync_enabled = db_user['sync_enabled']
        self.last_sync_timestamp = db_user.get('last_sync_timestamp', None)
        self.email_verified = db_user['email_verified']

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        if not self.email_verified:
            try:
                user = get_dynamodb_user(user_id=self.id, fields=['email_verified'])
                self.email_verified = bool(user['email_verified'])
            except ClientError as e:
                app.logger.error(
                    f"Failed to fetch user from DynamoDB to check email_verified: {e}"
                )

        return self.email_verified

@login_manager.user_loader
def load_user(user_id):
    """
    Loads a user for LoginManager

    Args:
        user_id (str): User ID from session token

    Returns:
        User: encapsulation of User for LoginManager
    """
    try:
        user = get_dynamodb_user(
            user_id=user_id,
            fields=[
                'id', 'email', 'anilist_user_id', 
                'email_verified', 'sync_enabled',
                'last_sync_timestamp'
            ]
        )
    except ClientError as e:
        app.logger.warning(f"LoginManager could not load user with id {user_id}: {e}")
        return None

    return User(user) if user else None

class AuthenticationResult:
    """
    Result after password authentication attempt. Uses standard HTTP status codes.
    """
    def __init__(self, *, code, user=None):
        self.code = code
        self.user = user

    @property
    def ok(self):
        return 200 <= self.code < 300

def verify_password(email, password):
    """
    Verifies that a password matches the email in the AniMalSync database.

    Args:
        email (str): The email of the account to check
        password (str): The inputted password

    Returns:
        (AuthenticationResult): result of authentication
    """
    # Fetch corresponding user to email from database
    try:
        user = get_dynamodb_user(
            email=email,
            fields=[
                'id', 'email', 'anilist_user_id', 
                'email_verified', 'sync_enabled',
                'last_sync_timestamp', 'password'
            ]
        )
    except ClientError as e:
        app.logger.error(
            f"Failed to fetch user from DynamoDB during login: {e}"
        )
        return AuthenticationResult(code=500)

    # Authenticate user login
    if not user: 
        return AuthenticationResult(code=401)

    peppered_password = password + app.config['SECRET_KEY']
    if not bcrypt.checkpw(
        peppered_password.encode('utf-8'),
        user['password'].encode('utf-8')
    ):
        return AuthenticationResult(code=401)
    
    return AuthenticationResult(code=200, user=user)