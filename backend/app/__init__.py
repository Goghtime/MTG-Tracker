from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

import os

app = Flask(__name__, static_folder='/static')
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://mtg_user:mtg_password@db/mtgdb')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = '/static/uploads'

login_manager = LoginManager(app)
login_manager.login_view = 'login'

from app.models import User, Commander  # Make sure to import your models here

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from app import routes
