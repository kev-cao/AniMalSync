import uuid
import bcrypt
import boto3
import secrets
import json
import time
import requests
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from flask import abort, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user, login_required
from app import app
from auth import User, login_manager
from forms import LoginForm, RegisterForm, AuthorizeMALForm, AutoSyncForm
from utils import (redirect_back, get_redirect_target, get_dynamodb_user,
                  update_dynamodb_user, get_anilist_username, mal_is_authorized)

class AuthenticationError(Exception):
    """
    Exception class for when user fails authentication.
    """
    pass

class InvalidVerificationError(Exception):
    """
    Exception class for when user uses an invalid email verification link.
    """
    pass

@app.route('/', methods=['GET'])
def home():
    """
    Home page of application
    """
    return render_template('home.html')

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    anilist_username = get_anilist_username(current_user.anilist_user_id)
    mal_form = AuthorizeMALForm()
    sync_form = AutoSyncForm()
    return render_template(
        'profile.html',
        anilist_username=anilist_username,
        mal_form=mal_form,
        sync_form=sync_form
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Only non-logged in users can log in
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    next_target = get_redirect_target()
    form = LoginForm()
    if form.validate_on_submit():
        # Fetch corresponding user to email from database
        try:
            user = get_dynamodb_user(
                email=form.email.data,
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
            form.errors_field.errors.append(
                "An issue occurred on the server. Please try again later."
            )

        # Authenticate user login
        try:
            if not user: 
                raise AuthenticationError()

            peppered_password = form.password.data + app.config['SECRET_KEY']
            if not bcrypt.checkpw(
                peppered_password.encode('utf-8'),
                user['password'].encode('utf-8')
            ):
                raise AuthenticationError()
            
            # Password authentication succeeded
            login_user(User(user), remember=form.remember_me.data, force=True)
        except AuthenticationError:
            form.errors_field.errors.append(
                "Login failed. Incorrect email or password."
            )
        else:
            return redirect_back(fallback='home')

    return render_template('login.html', form=form, next=next_target)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Only non-logged in users can register
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegisterForm()
    if form.validate_on_submit():
        # Generate salt and hash password
        # https://stackabuse.com/hashing-passwords-in-python-with-bcrypt/
        salt = bcrypt.gensalt()
        peppered_pass = form.password.data + app.config['SECRET_KEY']
        hashed_pwd = bcrypt.hashpw(peppered_pass.encode('utf-8'), salt).decode('utf-8')

        user_id = str(uuid.uuid4())
        # Dynamo item
        user = {
            'id': user_id,
            'email': form.email.data,
            'anilist_user_id': form.anilist_user_id,
            'password': hashed_pwd,
            'email_verified': False,
            'sync_enabled': False,
            'last_sync_timestamp': int(time.time())
        }

        # Add user to DynamoDB
        try:
            dynamo = boto3.resource(
                'dynamodb',
                region_name=app.config['AWS_REGION_NAME']
            )
            table = dynamo.Table(app.config['AWS_USER_DYNAMODB_TABLE'])
            table.put_item(Item=user)

            # Save user to session
            login_user(User(user), remember=form.remember_me.data, force=True)
        except ClientError as e:
            app.logger.error(f"Failed to add new registration to DynamoDB: {e}")
            form.errors_field.errors.append(
                "Failed to register account. Please try again later."
            )
        else:
            app.logger.debug(f"Registered user {form.email.data} with ID {user_id}")
            return redirect_back(fallback='home')

    return render_template('register.html', form=form, next='/verify')

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/logout', methods=['GET'])
def logout():
    logout_user()
    return redirect_back(fallback='home')

@app.route('/verify', methods=['GET'])
@login_required
def send_verify():
    if current_user.is_active:
        return redirect(url_for('home'))

    # Look for user and add verification code and timestamp.
    try:
        # Generate secret code for verification
        code = secrets.token_urlsafe(32)
        update_dynamodb_user(
            user_id=current_user.id,
            data={
                'verification_code': code,
                'verification_timestamp': int(time.time()) # Unix Epoch
            }
        )
    except ClientError as e:
        app.logger.error(f"Could not update user with verification data: {e}")
        return render_template(
            'send_verify.html',
            body="Could not find account. Please contact site owner."
        )
    
    # Generate and send email
    try:
        ses = boto3.client('ses', region_name=app.config['AWS_REGION_NAME'])
        verif_url = f"{request.host_url}/verification?email={current_user.email}&code={code}"
        ses.send_templated_email(
            Source=app.config['APP_EMAIL'],
            Destination={
                'ToAddresses': [current_user.email]
            },
            Template=app.config['VERIF_EMAIL_TEMPLATE'],
            TemplateData=json.dumps({
                'url': verif_url
            })
        )

        app.logger.debug(f"Sent verification email to {current_user.email}.")
        return render_template(
            'send_verify.html',
            body=("Email verification sent. You will have 5 minutes to verify your "
                  "email. It will take up to 60 seconds, and you may need to check "
                  "your spam folder. If you still do not see it, press the "
                  "'Resend Email' button below.")
        )
    except ClientError as e:
        app.logger.error(f"Failed to send verification email to {current_user.email}: {e}")
        return render_template(
            'send_verify.html',
            body=("Could not send verification email."
                  "Please try again by clicking 'Resend Email' button below.")
        )

@app.route('/verification', methods=['GET'])
@login_required
def verify_email():
    email = request.args.get('email')
    code = request.args.get('code')

    # Check if the verification link is valid
    try:
        user = get_dynamodb_user(
            email=email,
            fields=['verification_code', 'verification_timestamp']
        )

        curr_time = int(time.time()) 
        if code != user['verification_code']:
            raise InvalidVerificationError()
        elif curr_time - user['verification_timestamp'] > 60 * 5:
            app.logger.debug(f"Expired verification link for {email}")
            return render_template(
                'verification.html',
                body=("This verification link has expired. Please send "
                      "another link using the 'Resend Email' button below."),
                allow_resend=True
            )
    except (KeyError, ClientError, InvalidVerificationError) as e:
        app.logger.debug(f"Invalid verification link for {email}: {e}")
        return render_template(
            'verification.html',
            body=("This is an invalid email verification link. "
                    "If this was a mistake, sign into your account, go "
                    "to your profile and resend the link again.")
        )

    # Update that the user has verified their email
    try:
        dynamo = boto3.resource(
            'dynamodb',
            region_name=app.config['AWS_REGION_NAME']
        )
        table = dynamo.Table(app.config['AWS_USER_DYNAMODB_TABLE'])
        table.update_item(
            Key={ 'id': current_user.id },
            UpdateExpression=("SET email_verified = :verified "
                              "REMOVE verification_code, "
                              "verification_timestamp"),
            ExpressionAttributeValues={ ':verified': True }
        )

        app.logger.debug(f"Verified user email {email}.")
        return render_template(
            'verification.html',
            body="Your email address was successfully verified!"
        )
    except ClientError:
        app.logger.error(f"Failed to update email {email} as verified: {e}")
        return render_template(
            'verification.html',
            body=("An issue occurred on the server. Please resend the link "
                  "using the 'Resend Email' button below."),
            allow_resend=True
        )

@app.route('/mal_authorized', methods=['GET'])
@login_required
def mal_authorized():
    return {
        'authorized': mal_is_authorized(current_user)
    }, 200

@app.route('/authorize_mal', methods=['GET'])
def authorize_mal():
    user_id = request.args.get('state')
    auth_code = request.args.get('code')

    user = get_dynamodb_user(
        user_id=user_id,
        fields=['code_verifier']
    )

    if user is None or 'code_verifier' not in user:
        return render_template(
            'mal_auth.html',
            body="Bad MyAnimeList authorization link."
        )
    
    resp = requests.post("https://myanimelist.net/v1/oauth2/token", data={
        'client_id': app.config['MAL_CLIENT_ID'],
        'client_secret': app.config['MAL_CLIENT_SECRET'],
        'code': auth_code,
        'code_verifier': user['code_verifier'],
        'grant_type': 'authorization_code'
    })

    if not resp.ok:
        app.logger.warning(f"MAL OAuth failed for user {user_id}: {resp}")
        return render_template(
            'mal_auth.html',
            body=("MyAnimeList authorization failed. Please try again "
                  "by going to your profile and resending the authorization link.")
        )

    resp = resp.json()
    try:
        update_dynamodb_user(
            user_id=user_id,
            data={
                'mal_access_token': resp['access_token'],
                'mal_refresh_token': resp['refresh_token'],
                'sent_mal_auth_email': False
            }
        )
    except ClientError as e:
        app.logger.error(f"Could not update user {user_id} with MAL tokens: {e}")
        return render_template(
            'mal_auth.html',
            body=("MyAnimeList authorization failed. Please try again "
                  "by going to your profile and resending the authorization link.")
        )

    return render_template(
        'mal_auth.html',
        body="MyAnimeList successfully authorized. You may begin syncing."
    )

@app.route("/authorize_mal", methods=['POST'])
@login_required
def send_mal_auth_email():
    if mal_is_authorized(current_user):
        return {
            'success': False,
            'message': "You are already authorized! Did not send authorization email."
        }, 400

    failed = False
    try: 
        lambda_client = boto3.client('lambda', region_name=app.config['AWS_REGION_NAME'])
        resp = lambda_client.invoke(
            FunctionName=app.config['AWS_EMAIL_LAMBDA'],
            Payload=json.dumps({
                'user_id': current_user.id
            })
        )

        if resp['StatusCode'] != 200:
            app.logger.warning(
                f"Could not send authorization email for user {current_user.id}: {resp}"
            )
            failed = True
    except ClientError as e:
        app.logger.warning(
            f"Could not send authorization email for user {current_user.id}: {e}"
        )
        failed = True

    if failed:
        return {
            'success': False,
            'message': "Failed to send authorization email. Please try again later."
        }, 500
    else:
        return {
            'success': True,
            'message': "Successfully sent MAL authorization email to address on file."
        }, 200

    


@app.route('/autosync', methods=['PATCH'])
@login_required
def autosync():
    is_active = request.form.get('autosync')
    print(request.form)
    return { 'success': True }, 200

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login', next=request.full_path))
