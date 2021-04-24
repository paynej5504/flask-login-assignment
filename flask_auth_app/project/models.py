#import statements
from flask_login import UserMixin
from . import db

# create user model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) #required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))