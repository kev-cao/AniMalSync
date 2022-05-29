import uuid
import bcrypt
import boto3
from botocore.exceptions import ClientError
from flask import abort, redirect, render_template, request, session, url_for
from flask_login import current_user, login_user
from app import app
from auth import LoginForm, RegisterForm, User
from util import redirect_back, get_redirect_target

@app.route('/', methods=['GET'])
def home():
    """
    Home page of application
    """
    return render_template('home.html')

@app.route('/profile', methods=['GET'])
def profile():
    pass

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        return redirect('/login')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Only non-logged in users can register
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    next_target = get_redirect_target()
    form = RegisterForm()
    if form.validate_on_submit():
        # Generate salt and hash password
        salt = bcrypt.gensalt()
        peppered_pass = app.config['SECRET_KEY'] + form.password.data
        hashed_pwd = bcrypt.hashpw(peppered_pass.encode('utf-8'), salt).decode('utf-8')

        user_id = str(uuid.uuid4())
        # Dynamo item
        user = {
            'id': user_id,
            'email': form.email.data,
            'anilist_user_id': form.anilist_user_id,
            'password': hashed_pwd,
            'email_verified': False
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
            form.errors_field.errors.append("Failed to register account. Please try again later.")
        else:
            app.logger.debug(f"Registered user {form.email.data} with ID {user_id}")
            return redirect_back(fallback=url_for('home'))

    return render_template('register.html', form=form, next=next_target)

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/logout', methods=['GET'])
def logout():
    pass
