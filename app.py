from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from tasks import encrypt_file_task, decrypt_file_task
import os
import base64
import random
import string
import bcrypt
import requests
import time
from functools import wraps
from datetime import timedelta, datetime, timezone
import logging
from logging.handlers import RotatingFileHandler
from security import (
    is_valid_username, is_valid_password, check_login_attempts,
    record_login_attempt, get_client_ip, login_required,
    hash_password, verify_password, log_security_event
)

application = Flask(__name__)
application.secret_key = os.urandom(32)

# Configure SQLAlchemy
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shadowvault.db'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(application)

if not os.path.exists('logs'):
    os.makedirs('logs')
file_handler = RotatingFileHandler('logs/shadowvault.log', maxBytes=10240, backupCount=10, delay=True)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
application.logger.addHandler(file_handler)
application.logger.setLevel(logging.INFO)
application.logger.info('ShadowVault startup')

limiter = Limiter(
    app=application,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

application.config['UPLOAD_FOLDER'] = 'uploads'
application.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'enc'}
application.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
application.config['SESSION_COOKIE_SECURE'] = True
application.config['SESSION_COOKIE_HTTPONLY'] = True
application.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

YANDEX_DISK_TOKEN = "y0__xCFovnRAhiN7TUgw63YvhJ1ydLbGOl9G7phI57GUoYzBc9piA"


# Define SQLAlchemy models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    site = db.Column(db.String(255), default='default_site')
    passwords = db.relationship('Password', backref='user', lazy=True, cascade="all, delete-orphan")
    activities = db.relationship('UserActivity', backref='user', lazy=True, cascade="all, delete-orphan")


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)


class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Create all tables
with application.app_context():
    db.create_all()


@application.before_request
def before_request():
    if request.path.startswith('/static/'):
        return
    if not request.is_secure and not application.debug:
        return redirect(request.url.replace('http://', 'https://', 1))
    if 'user_id' in session:
        # Only update last_active timestamp
        session['last_active'] = datetime.now().isoformat()
    ip = get_client_ip()
    if not check_login_attempts(ip):
        application.logger.warning(f'Too many login attempts from IP: {ip}')
        return jsonify({"error": "Too many login attempts. Please try again later."}), 429


@application.route('/')
def index():
    return render_template('index/index.html')


@application.route('/terms')
def terms():
    return render_template('index/terms.html')


@application.route('/privacy')
def privacy():
    return render_template('index/privacy.html')


@application.route('/application')
@login_required
def app_dashboard():
    return render_template('dashboard.html')


@application.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        if not username or not password:
            return render_template('login.html', error="Заполните все поля")
        if not is_valid_username(username):
            return render_template('login.html', error="Некорректное имя пользователя")
        ip = get_client_ip()
        try:
            user = User.query.filter_by(username=username).first()
            if user and verify_password(password, user.password):
                if remember:
                    session.permanent = True
                session['user_id'] = user.id
                session['username'] = username
                session['ip'] = ip
                session['user_agent'] = request.user_agent.string
                session['last_active'] = datetime.now().isoformat()
                record_login_attempt(ip, True)
                log_security_event('login_success', f'User {username} logged in successfully', ip)
                next_page = request.args.get('next')
                if not next_page or not next_page.startswith('/'):
                    next_page = url_for('dashboard')
                return redirect(next_page)
            else:
                record_login_attempt(ip, False)
                log_security_event('login_failed', f'Failed login attempt for user {username}', ip)
                return render_template('login.html', error="Неверное имя пользователя или пароль")
        except Exception as e:
            application.logger.error(f'Database error during login: {e}')
            return render_template('login.html', error="Ошибка базы данных")
    message = request.args.get('message')
    return render_template('login.html', message=message)


@application.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    if request.method == 'POST':
        application.logger.info('Registration attempt received')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        application.logger.info(
            f'Registration data - username: {username}, password length: {len(password)}, confirm password length: {len(confirm_password)}')

        if not username or not password or not confirm_password:
            application.logger.warning('Registration failed: Empty fields')
            return render_template('register.html', error="Заполните все поля")
        if not is_valid_username(username):
            application.logger.warning(f'Registration failed: Invalid username format - {username}')
            return render_template('register.html',
                                   error="Имя пользователя должно содержать только буквы, цифры и знак подчеркивания")
        if not is_valid_password(password):
            application.logger.warning('Registration failed: Invalid password format')
            return render_template('register.html',
                                   error="Пароль должен содержать минимум 8 символов, включая цифры, строчные и заглавные буквы")
        if password != confirm_password:
            application.logger.warning('Registration failed: Passwords do not match')
            return render_template('register.html', error="Пароли не совпадают")
        ip = get_client_ip()
        try:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                application.logger.warning(f'Registration failed: Username already exists - {username}')
                return render_template('register.html', error="Имя пользователя уже занято")

            hashed_password = hash_password(password)
            max_user_id = db.session.query(db.func.max(User.user_id)).scalar()
            new_user_id = (max_user_id + 1) if max_user_id else 1

            new_user = User(
                user_id=new_user_id,
                username=username,
                password=hashed_password,
                site="default_site"
            )
            db.session.add(new_user)
            db.session.commit()

            application.logger.info(f'User successfully registered: {username}')
            log_security_event('registration_success', f'New user registered: {username}', ip)
            return redirect(url_for('login', success="Пользователь успешно зарегистрирован!"))
        except Exception as e:
            application.logger.error(f'Database error during registration: {e}')
            return render_template('register.html', error="Ошибка при добавлении пользователя")
    return render_template('register.html')


@application.route('/dashboard')
@login_required
def dashboard():
    try:
        user = db.session.get(User, session['user_id'])
        username = user.username if user else "Пользователь"
        recent_activities = UserActivity.query.filter_by(user_id=session['user_id']) \
            .order_by(UserActivity.created_at.desc()) \
            .limit(5) \
            .all()
        return render_template('dashboard.html',
                               username=username,
                               recent_activities=recent_activities)
    except Exception as e:
        application.logger.error(f'Database error in dashboard: {e}')
        return render_template('dashboard.html', error="Ошибка базы данных")


@application.route('/encryptor')
@login_required
def encryptor():
    return render_template('encryptor.html')


@application.route('/generator')
@login_required
def generator():
    return render_template('generator.html')


@application.route('/manager')
@login_required
def manager():
    try:
        passwords = Password.query.filter_by(user_id=session['user_id']).all()
        return render_template('manager.html', passwords=passwords)
    except Exception as e:
        application.logger.error(f'Database error in manager: {e}')
        return render_template('manager.html', error="Ошибка базы данных")


@application.route('/cloud')
@login_required
def cloud():
    return render_template('cloud.html')


@application.route('/settings')
@login_required
def settings():
    try:
        user = db.session.get(User, session['user_id'])
        return render_template('settings.html', username=user.username)
    except Exception as e:
        application.logger.error(f'Database error in settings: {e}')
        return render_template('settings.html', error="Ошибка базы данных")


@application.route('/logout')
def logout():
    if 'user_id' in session:
        log_security_event('logout', f'User {session.get("username")} logged out', session.get('ip'))
    session.clear()
    return redirect(url_for('login'))


@application.route('/api/generate_password', methods=['POST'])
@login_required
def api_generate_password():
    try:
        data = request.json
        print("Received data:", data)
        if not data:
            return jsonify({"error": "Отсутствуют данные"}), 400
        length = int(data.get('length', 16))
        include_uppercase = data.get('include_uppercase', True)
        include_lowercase = data.get('include_lowercase', True)
        include_digits = data.get('include_digits', True)
        include_symbols = data.get('include_symbols', True)
        exclude_similar = data.get('exclude_similar', False)
        use_passphrase = data.get('use_passphrase', False)
        print("Parameters:", {
            "length": length,
            "include_uppercase": include_uppercase,
            "include_lowercase": include_lowercase,
            "include_digits": include_digits,
            "include_symbols": include_symbols,
            "exclude_similar": exclude_similar,
            "use_passphrase": use_passphrase
        })
        if length < 8:
            return jsonify({"error": "Длина пароля должна быть не менее 8 символов"}), 400
        if length > 128:
            return jsonify({"error": "Длина пароля не должна превышать 128 символов"}), 400
        if not any([include_uppercase, include_lowercase, include_digits, include_symbols]):
            return jsonify({"error": "Выберите хотя бы один тип символов"}), 400
        if use_passphrase:
            words = [
                "apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "honeydew",
                "kiwi", "lemon", "mango", "orange", "papaya", "quince", "raspberry", "strawberry",
                "tangerine", "watermelon", "yuzu", "zucchini"
            ]
            num_words = max(3, min(5, length // 5))
            selected_words = random.sample(words, num_words)
            password = "-".join(selected_words)
            if len(password) < length:
                password += str(random.randint(100, 999))
        else:
            characters = ""
            if include_uppercase:
                characters += string.ascii_uppercase
            if include_lowercase:
                characters += string.ascii_lowercase
            if include_digits:
                characters += string.digits
            if include_symbols:
                characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if exclude_similar:
                characters = characters.replace("1", "").replace("l", "").replace("I", "")
                characters = characters.replace("0", "").replace("O", "")
                characters = characters.replace("5", "").replace("S", "")
                characters = characters.replace("2", "").replace("Z", "")
            if not characters:
                return jsonify({"error": "Нет доступных символов для генерации"}), 400
            password = ""
            required_chars = []
            if include_uppercase:
                required_chars.append(random.choice(string.ascii_uppercase))
            if include_lowercase:
                required_chars.append(random.choice(string.ascii_lowercase))
            if include_digits:
                required_chars.append(random.choice(string.digits))
            if include_symbols:
                required_chars.append(random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
            password = ''.join(required_chars)
            remaining_length = length - len(password)
            password += ''.join(random.choice(characters) for _ in range(remaining_length))
            password_list = list(password)
            random.shuffle(password_list)
            password = ''.join(password_list)
        log_user_activity(session['user_id'], 'generate_password', f'Сгенерирован пароль длиной {length} символов')
        return jsonify({"password": password})
    except Exception as e:
        application.logger.error(f"Error generating password: {e}")
        return jsonify({"error": "Ошибка генерации пароля"}), 500


@application.route('/api/add_password', methods=['POST'])
@login_required
def api_add_password():
    data = request.json
    site = data.get('site')
    username = data.get('username')
    password = data.get('password')
    if not site or not username or not password:
        return jsonify({"error": "Заполните все поля"}), 400
    try:
        new_password = Password(
            user_id=session['user_id'],
            site=site,
            username=username,
            password=password
        )
        db.session.add(new_password)
        db.session.commit()
        log_user_activity(session['user_id'], 'add_password', f'Добавлен пароль для сайта {site}')
        return jsonify({"success": "Пароль успешно добавлен!"})
    except Exception as e:
        application.logger.error(f'Database error in api_add_password: {e}')
        return jsonify({"error": f"Ошибка базы данных: {e}"}), 500


@application.route('/api/encrypt_text', methods=['POST'])
@login_required
def api_encrypt_text():
    try:
        data = request.json
        print("Received data:", data)
        if not data:
            return jsonify({"error": "Отсутствуют данные"}), 400
        text = data.get('text')
        password = data.get('password')
        algorithm = data.get('algorithm', 'AES-CBC')
        key_length = int(data.get('key_length', 256))
        print("Text:", text)
        print("Password:", password)
        if not text or not password:
            return jsonify({"error": "Заполните все поля", "received": {"text": text, "password": password}}), 400
        if not isinstance(text, str) or not isinstance(password, str):
            return jsonify(
                {"error": "Неверный формат данных", "types": {"text": type(text), "password": type(password)}}), 400
        if key_length not in [128, 192, 256]:
            return jsonify({"error": "Неподдерживаемая длина ключа"}), 400
        salt = os.urandom(16)
        key, _ = derive_key(password, key_length, salt)
        data_bytes = text.encode('utf-8')
        if algorithm == "AES-CBC":
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            padder = sym_padding.PKCS7(128).padder()
            encryptor = cipher.encryptor()
            padded_data = padder.update(data_bytes) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_text = base64.b64encode(salt + iv + ciphertext).decode('utf-8')
        elif algorithm == "TripleDES":
            iv = os.urandom(8)
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            padder = sym_padding.PKCS7(64).padder()
            encryptor = cipher.encryptor()
            padded_data = padder.update(data_bytes) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_text = base64.b64encode(salt + iv + ciphertext).decode('utf-8')
        elif algorithm == "Blowfish":
            iv = os.urandom(8)
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
            padder = sym_padding.PKCS7(64).padder()
            encryptor = cipher.encryptor()
            padded_data = padder.update(data_bytes) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_text = base64.b64encode(salt + iv + ciphertext).decode('utf-8')
        else:
            return jsonify({"error": "Неподдерживаемый алгоритм"}), 400
        return jsonify({"encrypted_text": encrypted_text})
    except ValueError as e:
        return jsonify({"error": f"Ошибка валидации данных: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Ошибка шифрования: {str(e)}"}), 500


@application.route('/api/decrypt_text', methods=['POST'])
@login_required
def api_decrypt_text():
    try:
        data = request.json
        print("Received data:", data)
        if not data:
            return jsonify({"error": "Отсутствуют данные"}), 400
        encrypted_text = data.get('encrypted_text')
        password = data.get('password')
        algorithm = data.get('algorithm', 'AES-CBC')
        key_length = int(data.get('key_length', 256))
        print("Encrypted text:", encrypted_text)
        print("Password:", password)
        if not encrypted_text or not password:
            return jsonify({"error": "Заполните все поля",
                            "received": {"encrypted_text": encrypted_text, "password": password}}), 400
        if not isinstance(encrypted_text, str) or not isinstance(password, str):
            return jsonify({"error": "Неверный формат данных",
                            "types": {"encrypted_text": type(encrypted_text), "password": type(password)}}), 400
        if key_length not in [128, 192, 256]:
            return jsonify({"error": "Неподдерживаемая длина ключа"}), 400
        try:
            data_bytes = base64.b64decode(encrypted_text)
        except Exception:
            return jsonify({"error": "Неверный формат зашифрованного текста"}), 400
        if len(data_bytes) < 24:
            return jsonify({"error": "Некорректные данные"}), 400
        salt = data_bytes[:16]
        if algorithm == "AES-CBC":
            if len(data_bytes) < 32:
                return jsonify({"error": "Некорректные данные"}), 400
            iv = data_bytes[16:32]
            ciphertext = data_bytes[32:]
            key, _ = derive_key(password, key_length, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            unpadder = sym_padding.PKCS7(128).unpadder()
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        elif algorithm == "TripleDES":
            if len(data_bytes) < 24:
                return jsonify({"error": "Некорректные данные"}), 400
            iv = data_bytes[16:24]
            ciphertext = data_bytes[24:]
            key, _ = derive_key(password, key_length, salt)
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            unpadder = sym_padding.PKCS7(64).unpadder()
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        elif algorithm == "Blowfish":
            if len(data_bytes) < 24:
                return jsonify({"error": "Некорректные данные"}), 400
            iv = data_bytes[16:24]
            ciphertext = data_bytes[24:]
            key, _ = derive_key(password, key_length, salt)
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
            unpadder = sym_padding.PKCS7(64).unpadder()
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        else:
            return jsonify({"error": "Неподдерживаемый алгоритм"}), 400
        try:
            return jsonify({"decrypted_text": plaintext.decode('utf-8')})
        except UnicodeDecodeError:
            return jsonify({"error": "Ошибка декодирования текста"}), 400
    except ValueError as e:
        return jsonify({"error": f"Ошибка валидации данных: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Ошибка расшифрования: {str(e)}"}), 500


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in application.config['ALLOWED_EXTENSIONS']


@application.route('/api/upload_file', methods=['POST'])
@login_required
def api_upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "Файл не выбран"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Файл не выбран"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(application.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({"success": "Файл успешно загружен", "filename": filename})
    return jsonify({"error": "Недопустимый тип файла"}), 400


@application.route('/api/encrypt_file', methods=['POST'])
@login_required
def api_encrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "Файл не выбран"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Файл не выбран"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "Неподдерживаемый тип файла"}), 400
        password = request.form.get('password')
        algorithm = request.form.get('algorithm', 'AES-CBC')
        save_to_cloud = request.form.get('save_to_cloud') == 'true'
        if not password:
            return jsonify({"error": "Введите пароль"}), 400
        os.makedirs(application.config['UPLOAD_FOLDER'], exist_ok=True)
        filename = secure_filename(file.filename)
        filepath = os.path.join(application.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        task_id = encrypt_file_task(filepath, password, algorithm, 256, session['user_id'], save_to_cloud)
        log_user_activity(session['user_id'], 'encrypt', f'Начато шифрование файла {filename}')
        return jsonify({"task_id": task_id})
    except Exception as e:
        application.logger.error(f"Error encrypting file: {str(e)}")
        return jsonify({"error": f"Ошибка при шифровании файла: {str(e)}"}), 500


@application.route('/api/task_status/<task_id>')
@login_required
def task_status(task_id):
    try:
        from tasks import get_task_status
        return jsonify(get_task_status(task_id))
    except Exception as e:
        application.logger.error(f"Error checking task status: {e}")
        return jsonify({
            'state': 'FAILURE',
            'status': 'Ошибка при проверке статуса задачи'
        }), 500


@application.route('/api/decrypt_file', methods=['POST'])
@login_required
def api_decrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "Файл не выбран"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Файл не выбран"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "Неподдерживаемый тип файла"}), 400
        password = request.form.get('password')
        algorithm = request.form.get('algorithm', 'AES-CBC')
        if not password:
            return jsonify({"error": "Введите пароль"}), 400
        os.makedirs(application.config['UPLOAD_FOLDER'], exist_ok=True)
        filename = secure_filename(file.filename)
        filepath = os.path.join(application.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        task_id = decrypt_file_task(filepath, password, algorithm, 256, session['user_id'])
        log_user_activity(session['user_id'], 'decrypt', f'Начато расшифрование файла {filename}')
        return jsonify({"task_id": task_id})
    except Exception as e:
        application.logger.error(f"Error decrypting file: {str(e)}")
        return jsonify({"error": f"Ошибка при расшифровке файла: {str(e)}"}), 500


@application.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        return send_from_directory(
            application.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except Exception as e:
        return jsonify({"error": f"Ошибка скачивания: {str(e)}"}), 500


def upload_to_cloud(filepath, user_id):
    try:
        headers = {"Authorization": f"OAuth {YANDEX_DISK_TOKEN}"}
        user_folder = f"ShadowVault/{user_id}"
        file_name = os.path.basename(filepath)
        folder_url = f"https://cloud-api.yandex.net/v1/disk/resources?path=/{user_folder}"
        response = requests.put(folder_url, headers=headers)
        if response.status_code not in [200, 201, 409]:
            logger.error(f"Failed to create folder: {response.text}")
            return None
        upload_url = f"https://cloud-api.yandex.net/v1/disk/resources/upload?path=/{user_folder}/{file_name}&overwrite=true"
        response = requests.get(upload_url, headers=headers)
        if response.status_code == 200:
            upload_link = response.json().get("href")
            with open(filepath, 'rb') as f:
                upload_response = requests.put(upload_link, files={"file": f})
                if upload_response.status_code == 201:
                    return f"/{user_folder}/{file_name}"
        logger.error(f"Upload failed: {response.text}")
        return None
    except Exception as e:
        logger.error(f"Cloud upload error: {str(e)}")
        return None


@application.route('/api/get_cloud_files', methods=['GET'])
@login_required
def api_get_cloud_files():
    try:
        headers = {"Authorization": f"OAuth {YANDEX_DISK_TOKEN}"}
        user_folder = f"ShadowVault/{session['user_id']}"
        url = f"https://cloud-api.yandex.net/v1/disk/resources?path=/{user_folder}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            files = response.json().get("_embedded", {}).get("items", [])
            encrypted_files = [f for f in files if f.get("name", "").endswith('.enc')]
            return jsonify({"files": encrypted_files})
        elif response.status_code == 404:
            requests.put(url, headers=headers)
            return jsonify({"files": []})
        else:
            return jsonify({"error": "Ошибка сервера"}), 500
    except Exception as e:
        return jsonify({"error": f"Ошибка подключения: {str(e)}"}), 500


@application.route('/api/download_file', methods=['POST'])
@login_required
def api_download_file():
    data = request.json
    path = data.get('path')
    try:
        headers = {"Authorization": f"OAuth {YANDEX_DISK_TOKEN}"}
        url = f"https://cloud-api.yandex.net/v1/disk/resources/download?path={path}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            download_url = response.json()["href"]
            file_response = requests.get(download_url)
            file_name = os.path.basename(path)
            filepath = os.path.join(application.config['UPLOAD_FOLDER'], file_name)
            with open(filepath, 'wb') as f:
                f.write(file_response.content)
            log_user_activity(session['user_id'], 'download', f'Скачан файл "{file_name}" из облака')
            return jsonify({
                "success": "Файл успешно скачан",
                "filename": file_name,
                "download_url": url_for('download_file', filename=file_name, _external=True)
            })
        else:
            return jsonify({"error": f"Ошибка сервера: {response.status_code}"}), 500
    except Exception as e:
        application.logger.error(f"Error downloading file from cloud: {e}")
        return jsonify({"error": f"Ошибка скачивания: {str(e)}"}), 500


@application.route('/api/delete_file', methods=['POST'])
@login_required
def api_delete_file():
    data = request.json
    path = data.get('path')
    try:
        headers = {"Authorization": f"OAuth {YANDEX_DISK_TOKEN}"}
        url = f"https://cloud-api.yandex.net/v1/disk/resources?path={path}"
        response = requests.delete(url, headers=headers)
        if response.status_code == 204:
            return jsonify({"success": "Файл удалён"})
        else:
            return jsonify({"error": "Не удалось удалить файл"}), 500
    except Exception as e:
        return jsonify({"error": f"Ошибка удаления: {str(e)}"}), 500


@application.route('/api/change_password', methods=['POST'])
@login_required
def api_change_password():
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    repeat_password = data.get('repeat_password')
    if not current_password or not new_password or not repeat_password:
        return jsonify({"error": "Заполните все поля"}), 400
    if new_password != repeat_password:
        return jsonify({"error": "Новые пароли не совпадают"}), 400
    if len(new_password) < 7:
        return jsonify({"error": "Пароль должен содержать не менее 7 символов"}), 400
    try:
        user = db.session.get(User, session['user_id'])
        if not verify_password(current_password, user.password):
            return jsonify({"error": "Неверный текущий пароль"}), 400
        user.password = hash_password(new_password)
        db.session.commit()
        return jsonify({"success": "Пароль успешно изменен!"})
    except Exception as e:
        application.logger.error(f'Database error in api_change_password: {e}')
        return jsonify({"error": f"Ошибка базы данных: {e}"}), 500


def derive_key(password, key_length, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length // 8,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode()), salt


def log_user_activity(user_id, action_type, details):
    try:
        activity = UserActivity(
            user_id=user_id,
            action_type=action_type,
            details=details,
            created_at=datetime.utcnow()
        )
        db.session.add(activity)
        db.session.commit()
        return True
    except Exception as e:
        application.logger.error(f"Ошибка логирования действия: {e}")
        return False


@application.route('/api/session_status')
def session_status():
    if 'user_id' in session:
        last_active = session.get('last_active')
        if last_active:
            last_active = datetime.fromisoformat(last_active)
            time_left = application.permanent_session_lifetime - (datetime.now() - last_active)
            return jsonify({
                'active': True,
                'time_left': time_left.total_seconds(),
                'username': session.get('username')
            })
    return jsonify({'active': False})


@application.route('/api/refresh_session')
def refresh_session():
    if 'user_id' in session:
        session['last_active'] = datetime.now().isoformat()
        return jsonify({'success': True})
    return jsonify({'success': False}), 401


@application.route('/api/update_password', methods=['POST'])
@login_required
def api_update_password():
    data = request.json
    password_id = data.get('id')
    site = data.get('site')
    username = data.get('username')
    password = data.get('password')
    
    if not password_id or not site or not username or not password:
        return jsonify({"error": "Заполните все поля"}), 400
        
    try:
        password_entry = Password.query.filter_by(id=password_id, user_id=session['user_id']).first()
        if not password_entry:
            return jsonify({"error": "Запись не найдена"}), 404
            
        password_entry.site = site
        password_entry.username = username
        password_entry.password = password
        
        db.session.commit()
        log_user_activity(session['user_id'], 'update_password', f'Обновлен пароль для сайта {site}')
        return jsonify({"success": "Пароль успешно обновлен!"})
    except Exception as e:
        application.logger.error(f'Database error in api_update_password: {e}')
        return jsonify({"error": f"Ошибка базы данных: {e}"}), 500


@application.route('/api/delete_password', methods=['POST'])
@login_required
def api_delete_password():
    data = request.json
    password_id = data.get('id')
    
    if not password_id:
        return jsonify({"error": "ID записи не указан"}), 400
        
    try:
        password_entry = Password.query.filter_by(id=password_id, user_id=session['user_id']).first()
        if not password_entry:
            return jsonify({"error": "Запись не найдена"}), 404
            
        db.session.delete(password_entry)
        db.session.commit()
        log_user_activity(session['user_id'], 'delete_password', f'Удален пароль для сайта {password_entry.site}')
        return jsonify({"success": "Пароль успешно удален!"})
    except Exception as e:
        application.logger.error(f'Database error in api_delete_password: {e}')
        return jsonify({"error": f"Ошибка базы данных: {e}"}), 500


@application.route('/api/recent_activities')
@login_required
def api_recent_activities():
    try:
        recent_activities = UserActivity.query.filter_by(user_id=session['user_id']) \
            .order_by(UserActivity.created_at.desc()) \
            .limit(5) \
            .all()
        
        # Convert to Moscow time (UTC+3)
        moscow_tz = timezone(timedelta(hours=3))
        
        activities = [{
            'action_type': activity.action_type,
            'details': activity.details,
            'created_at': activity.created_at.replace(tzinfo=timezone.utc).astimezone(moscow_tz).strftime('%d.%m.%Y %H:%M:%S')
        } for activity in recent_activities]
        
        application.logger.info(f'Recent activities for user {session["user_id"]}: {activities}')
        return jsonify({"activities": activities})
    except Exception as e:
        application.logger.error(f'Database error in api_recent_activities: {e}')
        return jsonify({"error": f"Ошибка базы данных: {e}"}), 500


if __name__ == '__main__':
    os.makedirs(application.config['UPLOAD_FOLDER'], exist_ok=True)
    application.run(debug=True)
