from . import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(255))
    commanders = db.relationship('Commander', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Commander(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100), nullable=False)
    color_identity = db.Column(db.String(20))
    image_url = db.Column(db.String(255))
    mana_cost = db.Column(db.String(50))
    cmc = db.Column(db.Integer)
    active = db.Column(db.Boolean, default=True)
    can_have_background = db.Column(db.Boolean, default=False)
    can_have_partner = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Commander {self.name}>'

class Deck(db.Model):
    __tablename__ = 'deck'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    commander_id = db.Column(db.Integer, db.ForeignKey('commander.id'), nullable=False)

    # Background related fields
    background_name = db.Column(db.String(100), nullable=True)
    background_mana_cost = db.Column(db.String(50), nullable=True)
    background_cmc = db.Column(db.Integer, nullable=True)
    background_image_url = db.Column(db.String(255), nullable=True)

    # Partner related fields
    partner_name = db.Column(db.String(100), nullable=True)
    partner_mana_cost = db.Column(db.String(50), nullable=True)
    partner_cmc = db.Column(db.Integer, nullable=True)
    partner_image_url = db.Column(db.String(255), nullable=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('decks', lazy=True))
    commander = db.relationship('Commander', backref=db.backref('decks', lazy=True))

def __repr__(self):
    details = f'<Deck User: {self.user_id}, Commander: {self.commander_id}'
    if self.background_name:
        details += f', Background: {self.background_name}'
    elif self.partner_name:
        details += f', Partner: {self.partner_name}'
    details += '>'
    return details

