from flask import render_template, redirect, url_for, flash, request, jsonify
from app import app, db
from app.models import User, Commander, Deck
from app.forms import LoginForm, RegistrationForm
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import logging
from flask import jsonify
from werkzeug.utils import secure_filename
import os


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
        user = User.query.filter((User.username == form.login.data) | (User.email == form.login.data)).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username, email, and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/account')
@login_required
def account():
    active_commanders = Commander.query.filter_by(user_id=current_user.id, active=True).all()
    retired_commanders = Commander.query.filter_by(user_id=current_user.id, active=False).all()
    return render_template('account.html', 
                           active_commanders=active_commanders, 
                           retired_commanders=retired_commanders)

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
        print("Received data:", data)  # Debugging line
        # Create and add new commander
        new_commander = Commander(
            user_id=current_user.id,
            name=data['name'],
            color_identity=data['color_identity'],
            image_url=data['image_url'],
            mana_cost=data['mana_cost'],
            cmc=data['cmc'],
            active=True,
            can_have_background=data.get('can_have_background', False),
            can_have_partner=data.get('can_have_partner', False)  # Assuming the frontend sends this data
        )
        db.session.add(new_commander)
        db.session.flush()  # Assigns an ID to new_commander

        # Check if a background or partner is provided and add to Deck
        if 'background' in data and data['background']:
            new_deck_entry = Deck(
                user_id=current_user.id,
                commander_id=new_commander.id,
                background_name=data['background']['name'],
                background_mana_cost=data['background'].get('mana_cost', ''),
                background_cmc=data['background'].get('cmc', None),
                background_image_url=data['background'].get('image_url', '')
            )
            db.session.add(new_deck_entry)
        elif 'partner' in data and data['partner']:
            new_deck_entry = Deck(
                user_id=current_user.id,
                commander_id=new_commander.id,
                partner_name=data['partner']['name'],
                partner_mana_cost=data['partner'].get('mana_cost', ''),
                partner_cmc=data['partner'].get('cmc', None),
                partner_image_url=data['partner'].get('image_url', '')
            )
            db.session.add(new_deck_entry)

        db.session.commit()

        return jsonify({'message': 'Commander added successfully'}), 201

    except KeyError as e:
        print("KeyError:", e)
        db.session.rollback()
        return jsonify({'error': f'Missing data for {e.args[0]}'}), 400
    except Exception as e:
        print("Exception:", e)
        db.session.rollback()
        logging.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/delete_commander/<int:commander_id>', methods=['POST'])
@login_required
def delete_commander(commander_id):
    commander = Commander.query.get(commander_id)
    if commander and commander.user_id == current_user.id:
        db.session.delete(commander)
        db.session.commit()
        flash('Commander deleted successfully', 'success')
        return jsonify({'message': 'Commander deleted successfully'}), 200
    else:
        flash('Commander not found or unauthorized', 'danger')
    return redirect(url_for('account'))

@app.route('/game_tracker')
def game_tracker():
    # Implement the logic for your 'Game Tracker' page here
    return render_template('game_tracker.html')

@app.route('/toggle_commander/<int:commander_id>', methods=['POST'])
@login_required
def toggle_commander(commander_id):
    commander = Commander.query.get_or_404(commander_id)
    commander.active = not commander.active  # Toggle the active status
    db.session.commit()
    return redirect(url_for('account'))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    user = User.query.filter_by(id=current_user.id).first()

    if not user or not check_password_hash(user.password_hash, current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('account'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('account'))

    # Update password
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash('Password updated successfully.', 'success')

    return redirect(url_for('account'))

@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('account'))
    
    file = request.files['avatar']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('account'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Here, update the user's avatar in the database
        current_user.avatar = file_path
        db.session.commit()

        flash('Avatar uploaded successfully', 'success')
        return redirect(url_for('account'))

    flash('Invalid file format', 'error')
    return redirect(url_for('account'))

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS