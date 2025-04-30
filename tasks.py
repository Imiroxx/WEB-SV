from threading import Thread, Lock
from queue import Queue
import logging
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from datetime import datetime


logging.basicConfig(
    filename='logs/tasks.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
task_queue = Queue()
task_results = {}
task_lock = Lock()


def task_worker():
    while True:
        task_id, func, args = task_queue.get()
        try:
            result = func(*args)
            with task_lock:
                task_results[task_id] = {
                    'state': 'SUCCESS',
                    'result': result
                }
        except Exception as e:
            logger.error(f"Error in task {task_id}: {e}")
            with task_lock:
                task_results[task_id] = {
                    'state': 'FAILURE',
                    'error': str(e)
                }
        task_queue.task_done()


worker_thread = Thread(target=task_worker, daemon=True)
worker_thread.start()


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


def encrypt_file(filepath, password, algorithm, key_length, user_id, save_to_cloud=False):
    try:
        logger.info(f"Starting encryption for file: {filepath}")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл не найден: {filepath}")
        with open(filepath, 'rb') as f:
            data_bytes = f.read()
        salt = os.urandom(16)
        key, _ = derive_key(password, key_length, salt)
        if algorithm == "AES-CBC":
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            padder = sym_padding.PKCS7(128).padder()
            encryptor = cipher.encryptor()
            padded_data = padder.update(data_bytes) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = salt + iv + ciphertext
        elif algorithm == "TripleDES":
            iv = os.urandom(8)
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            padder = sym_padding.PKCS7(64).padder()
            encryptor = cipher.encryptor()
            padded_data = padder.update(data_bytes) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = salt + iv + ciphertext
        elif algorithm == "Blowfish":
            iv = os.urandom(8)
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
            padder = sym_padding.PKCS7(64).padder()
            encryptor = cipher.encryptor()
            padded_data = padder.update(data_bytes) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = salt + iv + ciphertext
        else:
            raise ValueError("Неподдерживаемый алгоритм")
        filename = os.path.basename(filepath)
        encrypted_filename = f"enc_{filename}.enc"
        encrypted_filepath = os.path.join('uploads', encrypted_filename)
        os.makedirs('uploads', exist_ok=True)
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)
        cloud_path = None
        if save_to_cloud:
            from app import upload_to_cloud
            cloud_path = upload_to_cloud(encrypted_filepath, user_id)
            if not cloud_path:
                logger.error("Не удалось загрузить файл в облачное хранилище")
        if os.path.exists(filepath):
            os.remove(filepath)
        from app import log_user_activity
        log_user_activity(user_id, 'encrypt', f'Зашифрован файл "{filename}" с помощью {algorithm}')

        return {
            "success": True,
            "filename": encrypted_filename,
            "cloud_path": cloud_path
        }
    except Exception as e:
        logger.error(f"Error in encryption: {str(e)}")
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except:
                pass
        raise


def decrypt_file(filepath, password, algorithm, key_length, user_id):
    try:
        logger.info(f"Starting decryption for file: {filepath}")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл не найден: {filepath}")
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        if len(encrypted_data) < 24:
            raise ValueError("Некорректные данные")
        salt = encrypted_data[:16]
        if algorithm == "AES-CBC":
            if len(encrypted_data) < 32:
                raise ValueError("Некорректные данные")
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            key, _ = derive_key(password, key_length, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            unpadder = sym_padding.PKCS7(128).unpadder()
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        elif algorithm == "TripleDES":
            if len(encrypted_data) < 24:
                raise ValueError("Некорректные данные")
            iv = encrypted_data[16:24]
            ciphertext = encrypted_data[24:]
            key, _ = derive_key(password, key_length, salt)
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            unpadder = sym_padding.PKCS7(64).unpadder()
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        elif algorithm == "Blowfish":
            if len(encrypted_data) < 24:
                raise ValueError("Некорректные данные")
            iv = encrypted_data[16:24]
            ciphertext = encrypted_data[24:]
            key, _ = derive_key(password, key_length, salt)
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
            unpadder = sym_padding.PKCS7(64).unpadder()
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        else:
            raise ValueError("Неподдерживаемый алгоритм")
        filename = os.path.basename(filepath)
        if filename.endswith('.enc'):
            decrypted_filename = filename[:-4]
        else:
            decrypted_filename = filename + '.dec'
        decrypted_filepath = os.path.join('uploads', decrypted_filename)
        os.makedirs('uploads', exist_ok=True)
        with open(decrypted_filepath, 'wb') as f:
            f.write(plaintext)
        if os.path.exists(filepath):
            os.remove(filepath)
        from app import log_user_activity
        log_user_activity(user_id, 'decrypt', f'Расшифрован файл "{filename}" с помощью {algorithm}')
        return {"success": True, "filename": decrypted_filename}
    except Exception as e:
        logger.error(f"Error in decryption: {str(e)}")
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except:
                pass
        raise


def encrypt_file_task(filepath, password, algorithm, key_length, user_id, save_to_cloud=False):
    task_id = f"encrypt_{datetime.now().strftime('%Y%m%d%H%M%S')}_{os.urandom(4).hex()}"
    task_queue.put((task_id, encrypt_file, (filepath, password, algorithm, key_length, user_id, save_to_cloud)))
    with task_lock:
        task_results[task_id] = {'state': 'PENDING'}
    return task_id


def decrypt_file_task(filepath, password, algorithm, key_length, user_id):
    task_id = f"decrypt_{datetime.now().strftime('%Y%m%d%H%M%S')}_{os.urandom(4).hex()}"
    task_queue.put((task_id, decrypt_file, (filepath, password, algorithm, key_length, user_id)))
    with task_lock:
        task_results[task_id] = {'state': 'PENDING'}
    return task_id


def get_task_status(task_id):
    with task_lock:
        if task_id not in task_results:
            return {'state': 'PENDING', 'status': 'Задача не найдена'}
        result = task_results[task_id]
        if result['state'] == 'SUCCESS':
            return {
                'state': 'SUCCESS',
                'status': 'Операция успешно завершена',
                'filename': result['result'].get('filename')
            }
        elif result['state'] == 'FAILURE':
            return {
                'state': 'FAILURE',
                'status': result.get('error', 'Ошибка при обработке файла')
            }
        return {'state': 'PENDING', 'status': 'Задача в процессе выполнения'}
