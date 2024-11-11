import os
import socketio
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, send, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Setup SQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///techtalk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/uploads')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Flask-SocketIO
socket_io = SocketIO(app)

#OOP
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(150), nullable=False)
    avatar = db.Column(db.String(150), nullable=True, default='default_avatar.jpg')
    bio = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

#Create and output when success
with app.app_context():
    db.create_all()  
    print("Database tables created")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Main Page
@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')


# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        
        # Check email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already registered. Please use a different email.', 'danger')
            return redirect(url_for('register'))
        
        if password == confirm_password:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            
            new_user = User(username=username, email=email, password_hash=password_hash)
            db.session.add(new_user)
            db.session.commit()
            
            flash('You are now registered and can log in!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match', 'danger')
    
    return render_template('register.html')


# Login then allow WebSocket 
@socket_io.on('message')
@login_required
def handleMessage(msg):
    print(f'Message: {msg}')
    send(f'{current_user.username}: {msg}', broadcast=True)

# Sign out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Update profile
@app.route('/account_settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    if request.method == 'POST':
        # Current info
        username = request.form['username']
        bio = request.form['bio']
        avatar = request.files['avatar']

        # New username
        current_user.username = username
        
        # New bio
        current_user.bio = bio

        # CHange pfp
        if avatar:
            avatar_filename = secure_filename(avatar.filename)
            avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], avatar_filename)
            avatar.save(avatar_path)
            current_user.avatar = avatar_filename

        # Save to database
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account_settings'))

    return render_template('account_settings.html')

if __name__ == "__main__":
    socket_io.run(app, debug=True)
