import re
import time
import logging
from functools import wraps
from flask import request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
login_attempts = {}


def is_valid_username(username):
    if not username or len(username) < 5:
        return False
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    return True


def is_valid_password(password):
    if not password or len(password) < 8:
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[A-Z]', password):
        return False
    return True


def check_login_attempts(ip):
    if ip in login_attempts:
        attempts, timestamp = login_attempts[ip]
        if attempts >= 5:
            if time.time() - timestamp < 300:
                return False
            else:
                login_attempts[ip] = (0, time.time())
    return True


def record_login_attempt(ip, success):
    if success:
        if ip in login_attempts:
            del login_attempts[ip]
    else:
        attempts, timestamp = login_attempts.get(ip, (0, time.time()))
        login_attempts[ip] = (attempts + 1, timestamp)


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('ip') != get_client_ip():
            session.clear()
            return redirect(url_for('login'))
        if session.get('user_agent') != request.user_agent.string:
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def hash_password(password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')


def verify_password(password, hashed_password):
    try:
        # Convert password to bytes if it's a string
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        # Convert hashed_password to bytes if it's a string
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
            
        return bcrypt.checkpw(password, hashed_password)
    except Exception as e:
        logging.error(f'Password verification error: {e}')
        return False


def log_security_event(event_type, details, ip=None):
    if ip is None:
        ip = get_client_ip()
    logging.info(f'Security Event - Type: {event_type}, IP: {ip}, Details: {details}')
