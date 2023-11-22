from flask import render_template, redirect, url_for, flash, request, jsonify
from app import app, db
from app.models import User, Commander
from app.forms import LoginForm, RegistrationForm
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import requests

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/account')
@login_required
def account():
    # Fetch commanders associated with the current user
    commanders = Commander.query.filter_by(user_id=current_user.id).all()
    return render_template('account.html', title='Account', commanders=commanders)

@app.route('/search_commanders', methods=['GET'])
def search_commanders():
    search_term = request.args.get('q', '')
    response = requests.get(f"https://api.scryfall.com/cards/search?q={search_term}+type:legendary+is:commander")
    if response.status_code == 200:
        return jsonify(response.json()['data']), 200
    else:
        return jsonify({"error": "Commanders not found"}), response.status_code

@app.route('/add_commander', methods=['POST'])
@login_required
def add_commander():
    try:
        data = request.get_json()

        if not data or 'name' not in data:
            return jsonify({'error': 'Missing commander name'}), 400

        # Creating a new Commander instance
        new_commander = Commander(
            user_id=current_user.id,  # Link to the current logged-in user
            name=data['name'],
            # Add other fields if necessary
        )
        db.session.add(new_commander)
        db.session.commit()

        return jsonify({'message': 'Commander added successfully'}), 201

    except KeyError as e:
        return jsonify({'error': f'Missing data for {e.args[0]}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
