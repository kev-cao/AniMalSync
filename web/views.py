from flask import (abort, redirect, render_template, request, session, url_for)
from app import app

@app.route('/', methods=['GET'])
def home():
    """
    Home page of application
    """
    return render_template('home.html')

@app.route('/profile', methods=['GET'])
def profile():
    pass

@app.route('/login', methods=['GET'])
def login():
    pass

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/logout', methods=['GET'])
def logout():
    pass
