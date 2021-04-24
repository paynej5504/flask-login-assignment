#import statements
from flask import Blueprint, render_template
from . import db
from flask_login import login_required, current_user

main = Blueprint('main', __name__)

#route to main page
@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
# profile page of current user
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)