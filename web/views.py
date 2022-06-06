import uuid, boto3, secrets, json, time, requests, os, random
from urllib import parse as url_parse
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from flask import redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from app import app
from auth import User, login_manager, verify_password
from forms import ChangeAniListUsernameForm, ChangeEmailForm, ChangePasswordForm, ForgotPasswordForm, LoginForm, RegisterForm, ResetPasswordForm
from utils import (hash_password, redirect_back, get_redirect_target, get_dynamodb_user,
                  update_dynamodb_user, get_anilist_username, mal_is_authorized,
                  schedule_sync)

os.environ['TZ'] = "America/New_York"
time.tzset()

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
    images_dir = os.path.join(app.static_folder, 'assets/images/carousel')
    images = os.listdir(images_dir)
    images = list(map(lambda i : (os.path.join('assets/images/carousel', i)), images))
    random.shuffle(images)
    return render_template('home.html', images=images)

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    anilist_username = get_anilist_username(current_user.anilist_user_id)
    mal_form = FlaskForm()
    sync_form = FlaskForm()
    email_form = ChangeEmailForm()
    password_form = ChangePasswordForm()
    anilist_form = ChangeAniListUsernameForm()
    unauth_mal_form = FlaskForm()

    dynamo = boto3.resource(
        'dynamodb',
        region_name=app.config['AWS_REGION_NAME']
    )

    try:
        table = dynamo.Table(app.config['AWS_LOG_DYNAMODB_TABLE'])
        logs = table.query(
            IndexName='user_id-timestamp-index',
            ProjectionExpression=('success,media_type,title,'
                                  '#st,progress,score,#ts'),
            KeyConditionExpression=Key('user_id').eq(current_user.id),
            ExpressionAttributeNames={
                '#ts': 'timestamp',
                '#st': 'status'
            }
        )['Items'][::-1]

        # Format timestamp from epoch to human readable
        for log in logs:
            log['timestamp'] = time.strftime(
                '%I:%M %p %Z | %m/%d/%Y',
                time.localtime(int(log['timestamp']))
            )
    except ClientError as e:
        app.logger.error(
            f"[User {current_user.id}] Failed to fetch sync logs: {e}"
        )
        logs = []


    log_headers = {
        'Media Type': 'media_type',
        'Title': 'title',
        'Status': 'status',
        'Progress': 'progress',
        'Score': 'score',
        'Timestamp': 'timestamp'
    }

    if current_user.last_sync_timestamp:
        last_sync = time.strftime(
            '%I:%M %p %Z | %m/%d/%Y',
            time.localtime(int(current_user.last_sync_timestamp))
        )
    else:
        last_sync = "Never"

    return render_template(
        'profile.html',
        anilist_username=anilist_username,
        log_headers=log_headers,
        last_sync=last_sync,
        logs=logs,
        mal_form=mal_form,
        sync_form=sync_form,
        email_form=email_form,
        password_form=password_form,
        anilist_form=anilist_form,
        unauth_mal_form=unauth_mal_form
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Only non-logged in users can log in
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    next_target = get_redirect_target()
    form = LoginForm()
    if form.validate_on_submit():
        result = verify_password(form.email.data, form.password.data)

        if result.ok:
            login_user(User(result.user), remember=form.remember_me.data, force=True)
            return redirect_back(fallback='home')
        else:
            if result.code == 401:
                msg = "Login failed. Incorrect email or password."
            else:
                msg = "An issue occurred on the server. Please try again later."
            form.errors_field.errors.append(msg)


    return render_template('login.html', form=form, next=next_target)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Only non-logged in users can register
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pwd = hash_password(form.password.data)
        user_id = str(uuid.uuid4())

        # Dynamo item
        user = {
            'id': user_id,
            'email': form.email.data,
            'anilist_user_id': form.anilist_user_id,
            'password': hashed_pwd,
            'email_verified': False,
            'sync_enabled': False
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

# So technically, I shouldn't do a "send email" operation like
# this using GET. However, I also shouldn't eat a double stacked
# extra cheese bacon cheeseburger, but here I am.
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
        urlsafe_email = url_parse.quote_plus(current_user.email)
        verif_url = f"{request.host_url}/verification?email={urlsafe_email}&code={code}"
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
        if not user or 'verification_code' not in user \
                or code != user['verification_code']:
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
        update_dynamodb_user(
            user_id=current_user.id,
            data={
                'email_verified': True,
                'verification_code': None,
                'verification_timestamp': None
            }
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
        fields=['code_verifier', 'sync_enabled']
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

    # If the user's sync is enabled, send another request for sync.
    if user['sync_enabled']:
        try:
            schedule_sync(user_id=user_id, now=True)
        except ClientError as e:
            app.logger.error(
                f"[User {user_id}] Failed to start new sync after MAL auth: {e}"
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
    enable = bool(int(request.form.get('autosync')))

    if enable:
        if not mal_is_authorized(current_user):
            return {
                'success': False,
                'message': "Your MAL account must be authorized before you can enable syncing."
            }, 401
        elif not current_user.is_active:
            return {
                'success': False,
                'message': "Your email address on file must be verified before you can enable syncing."
            }, 401

        try:
            schedule_sync(user_id=current_user.id, now=True)
        except ClientError as e:
            app.logger.error(f"Failed to schedule sync for user {current_user.id}: {e}")
            return {
                'success': False,
                'message': "Sync failed. Please try again later."
            }, 500
        else:
            try:
                update_dynamodb_user(
                    user_id=current_user.id,
                    data={ 'sync_enabled': enable }
                )
            except ClientError as e:
                app.logger.error(
                    f"[User {current_user.id}] Failed to enable auto-sync: {e}"
                )
                return {
                    'success': False,
                    'message': "Sync scheduled, but failed to enable auto-sync. Please try again later."
                }, 500

        return {
            'success': True,
            'message': "Successfully scheduled sync and enabled auto-sync."
        }, 201
    else:
        sfn = boto3.client('stepfunctions', region_name=app.config['AWS_REGION_NAME'])
        try:
            user = get_dynamodb_user(
                user_id=current_user.id,
                fields=['sync_sfn']
            )
            if 'sync_sfn' in user:
                try:
                    sfn_exec = sfn.describe_execution(executionArn=user['sync_sfn'])
                    if sfn_exec['status'] == 'RUNNING':
                        sfn.stop_execution(
                            executionArn=user['sync_sfn'],
                            cause=(f"[User {current_user.id}] Cancelling auto-sync, "
                                "so cancel running SFN.")
                        )
                except ClientError as e:
                    app.logger.warning(
                        (f"[User {current_user.id}] Failure when "
                         f"cancelling any running SFN: {e}")
                    )
                update_dynamodb_user(
                    user_id=current_user.id,
                    data={
                        'sync_sfn': None
                    }
                )
        except ClientError as e:
            app.logger.error((f"[User {current_user.id}] DynamoDB user failure "
                              f"getting/updating user: {e}"))

        try:
            update_dynamodb_user(
                user_id=current_user.id,
                data={
                    'sync_enabled': enable,
                }
            )
        except ClientError as e:
            app.logger.error(
                f"[User {current_user.id}] Failed to disable auto-sync: {e}"
            )
            return {
                'success': False,
                'message': "Failed to disable auto-sync. Please try again later."
            }, 500

        return {
            'success': True,
            'message': "Successfully disabled auto-sync."
        }, 201

@app.route('/change_email', methods=['PATCH'])
@login_required
def change_email():
    email_form = ChangeEmailForm()
    status = 400

    if email_form.validate():
        result = verify_password(
            current_user.email,
            email_form.password.data
        )
        if result.ok:
            try:
                new_email = email_form.email.data
                update_dynamodb_user(
                    user_id=current_user.id,
                    data={
                        'email': new_email,
                        'email_verified': False,
                        'sync_enabled': False
                    }
                )
                current_user.email = new_email
                return { 'success': True }, 201
            except ClientError as e:
                app.logger.error(
                    f"[User {current_user.id}] AWS error when updating email: {e}"
                )
                email_form.errors_field.errors.append(
                    "An issue occurred on the server. Please try again later."
                )
                status = 500
        else:
            email_form.errors_field.errors.append("Incorrect password.")
            status = 401

    return render_template('change_email_modal.html', email_form=email_form), status

@app.route('/change_password', methods=['PATCH'])
@login_required
def change_password():
    password_form = ChangePasswordForm()
    status = 400

    if password_form.validate():
        result = verify_password(
            current_user.email,
            password_form.password.data
        )

        if result.ok:
            new_password = password_form.new_password.data
            if new_password == password_form.password.data:
                password_form.errors_field.errors.append(
                    "You have entered the same password as your current password."
                )
            else:
                try:
                    hashed_pass = hash_password(password_form.new_password.data)
                    update_dynamodb_user(
                        user_id=current_user.id,
                        data={
                            'password': hashed_pass
                        }
                    )
                    return {
                        'success': True,
                        'message': "Successfully changed password."
                    }, 201
                except ClientError as e:
                    app.logger.error(
                        f"[User {current_user.id}] AWS error when updating password: {e}"
                    )
                    password_form.errors_field.errors.append(
                        "An issue occurred on the server. Please try again later."
                    )
                    status = 500
        else:
            password_form.password.errors.append("Incorrect password.")
            status = 401
    
    return render_template('change_password_modal.html', password_form=password_form), status

@app.route('/change_anilist', methods=['PATCH'])
@login_required
def change_anilist():
    anilist_form = ChangeAniListUsernameForm()
    status = 404
    if anilist_form.validate():
        if anilist_form.anilist_user_id == current_user.anilist_user_id:
            anilist_form.anilist_user.errors.append(
                "AniList username already connected to this account."
            )
            status = 400
        else:
            try:
                update_dynamodb_user(
                    user_id=current_user.id,
                    data={
                        'anilist_user_id': anilist_form.anilist_user_id
                    }
                )
                current_user.anilist_user_id = anilist_form.anilist_user_id
                return {
                    'success': True,
                    'anilist_username': anilist_form.anilist_user.data,
                    'message': "Successfully connected to new AniList user."
                }, 201
            except ClientError as e:
                app.logger.error(
                    f"[User {current_user.id}] AWS error while updating AniList user: {e}"
                )
                status = 500 

    return render_template('change_anilist_modal.html', anilist_form=anilist_form), status

@app.route('/unauthorize_mal', methods=['PATCH'])
@login_required
def unauthorize_mal():
    try:
        update_dynamodb_user(
            user_id=current_user.id,
            data={
                'mal_access_token': None,
                'mal_refresh_token': None,
                'sync_enabled': False
            }
        )

        return {
            'success': True,
            'message': "Successfully removed MAL credentials from AniMalSync and disabled syncing."
        }, 201
    except ClientError as e:
        app.logger.error(f"[User {current_user.id}] AWS error while unauthorizing MAL: {e}")
        return {
            'success': False,
            'message': "An issue occurred on the server. Please try again later."
        }, 500

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Do not allow logged in users to access this page
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    sent_email = False

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        try:
            user = get_dynamodb_user(
                email=email,
                fields=['id']
            )

            if not user:
                sent_email = True # Do not allow user to know that no account was found
            else:
                code = secrets.token_urlsafe(32)
                update_dynamodb_user(
                    user_id=user['id'],
                    data={
                        'reset_password_code': code,
                        'reset_password_timestamp': int(time.time())
                    }
                )
                urlsafe_email = url_parse.quote_plus(email)
                reset_url = f"{request.host_url}/reset_password?email={urlsafe_email}&code={code}"
                ses = boto3.client('ses', region_name=app.config['AWS_REGION_NAME'])
                ses.send_templated_email(
                    Source=app.config['APP_EMAIL'],
                    Destination={
                        'ToAddresses': [email]
                    },
                    Template=app.config['RESET_PASSWORD_EMAIL_TEMPLATE'],
                    TemplateData=json.dumps({
                        'url': reset_url
                    })
                )
                app.logger.info(f"Sent password reset email to {email}.")
                sent_email = True
        except ClientError as e:
            app.logger.error(
                f"[User {current_user.id}] AWS error while sending reset email: {e}"
            )
            form.errors_field.errors.append(
                "An issue occurred on the server. Please try again later."
            )
            sent_email = False
    return render_template('forgot_password.html', form=form, sent_email=sent_email)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Do not allow logged in users to access this page
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = ResetPasswordForm()
    # If this is a GET request, check if reset link is valid
    if request.method == 'GET':
        email = request.args.get('email')
        code = request.args.get('code')
        try:
            user = get_dynamodb_user(
                email=email,
                fields=['id', 'reset_password_code', 'reset_password_timestamp']
            )

            curr_time = int(time.time())
            if not user or 'reset_password_code' not in user \
                    or code != user['reset_password_code']:
                return render_template(
                    'reset_password.html',
                    valid_link=False,
                    invalid_msg="Password reset link is invalid."
                )
            elif curr_time - user['reset_password_timestamp'] > 60 * 5:
                app.logger.debug(f"Expired password reset link for {email}")
                return render_template(
                    'reset_password.html',
                    valid_link=False,
                    invalid_msg="Password reset link has expired."
                )
            
            form.user_id_field.data = user['id']
        except ClientError as e:
            app.logger.error(
                f"AWS error while checking validity of password reset link: {e}"
            )
            return render_template(
                'reset_password.html',
                valid_link=False,
                invalid_msg="An issue occurred on the server. Please try again later."
            )

    if form.validate_on_submit():
        try:
            user_id = form.user_id_field.data
            hashed_pass = hash_password(form.password.data)
            update_dynamodb_user(
                user_id=user_id,
                data={
                    'password': hashed_pass,
                    'reset_password_code': None,
                    'reset_password_timestamp': None
                }
            )
            app.logger.info(f"[User {user_id}] Reset their password.")
            return redirect(url_for('home'))
        except ClientError as e:
            app.logger.error(
                f"[User {user_id}] AWS error while resetting new password: {e}"
            )
            form.errors_field.errors.append(
                "An error occurred on the server. Please try again later."
            )

    return render_template('reset_password.html', valid_link=True, form=form)
    


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login', next=request.full_path))
