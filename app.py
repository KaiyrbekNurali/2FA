from flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
from config import Config
from models import User
from extensions import db, mail
from random import randint
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
mail.init_app(app)
migrate = Migrate(app, db)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            code = str(randint(100000, 999999))
            user.two_factor_code = code
            db.session.commit()
            msg = Message('Your 2FA Code', sender='noreply@example.com', recipients=[user.email])
            msg.body = f'Your 2FA code is {code}'
            mail.send(msg)
            session['username'] = username
            flash('A 2FA code has been sent to your email.', 'info')
            return redirect(url_for('verify_2fa'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        code = request.form.get('code')
        username = session.get('username')
        user = User.query.filter_by(username=username).first()
        if user and user.two_factor_code == code:
            user.two_factor_code = None
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid 2FA code', 'danger')
    return render_template('verify_2fa.html')

@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)
