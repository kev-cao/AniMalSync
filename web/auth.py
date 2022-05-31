# auth.py
# Sets up authorization and functions for Flask-Login
###

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
        self.last_sync_timestamp = db_user['last_sync_timestamp']
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
