#import statements
from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from flask_login import login_user, logout_user, login_required
from .models import User
from . import db
auth = Blueprint('auth', __name__)

# login page route
@auth.route('/login')
def login():
    return render_template('login.html')

# what happens after a user logs in
@auth.route('/login', methods=['POST'])
def login_post():
    #get email and password entered
    email = request.form.get('email')
    password = request.form.get('password')
    # check if selected "remember me" checkbox
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))  # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    #login code
    return redirect(url_for('main.profile'))

# signup page route
@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    #get email, name, and password
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    #if a user is returned, they are already in the db
    user = User.query.filter_by(email=email).first()

    # redirect back to signup page if user is found
    if user:
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))
    # create new user and hash password
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    #add user to database
    db.session.add(new_user)
    db.session.commit()

    #validate and add user to database
    return redirect(url_for('auth.login'))

# logout route
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))