from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, g, make_response
import hashlib
import os
from datetime import datetime
import sqlite3
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'supersecretkey'

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE = os.path.join(UPLOAD_FOLDER, 'blockchain.db')

ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

users = {'bharath': 'password','teja': 'password'}
admins = {'admin': 'password'}

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blockchain (
                block_index INTEGER,
                previous_hash TEXT,
                timestamp TEXT,
                data TEXT,
                hash TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_files (
                username TEXT,
                filename TEXT
            )
        ''')
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

class Block:
    def __init__(self, block_index, previous_hash, timestamp, data, hash_value):
        self.block_index = block_index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash_value

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + str(previous_hash) + str(timestamp) + str(data)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

init_db()

@app.route('/')
def index():
    if 'username' in session:
        user = session['username']
        if user in admins:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT * FROM blockchain')
            blockchain_data = cursor.fetchall()
            blockchain = []
            for block_data in blockchain_data:
                block = Block(block_data[0], block_data[1], block_data[2], block_data[3], block_data[4])
                blockchain.append(block)
            return render_template('index.html', blockchain=blockchain, is_admin=True)
        else:
            cursor = get_db().cursor()
            cursor.execute('SELECT * FROM user_files WHERE username=?', (user,))
            files_data = cursor.fetchall()
            files = [file_data[1] for file_data in files_data]
            return render_template('index.html', files=files, is_admin=False)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        elif username in admins and admins[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users[username] = password
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        return redirect(request.url)
    
    encrypted_data = cipher_suite.encrypt(file.read())
    
    with open(os.path.join(UPLOAD_FOLDER, file.filename), 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    
    user = session['username']
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM blockchain')
    blockchain_data = cursor.fetchall()
    blockchain = []
    for block_data in blockchain_data:
        block = Block(block_data[0], block_data[1], block_data[2], block_data[3], block_data[4])
        blockchain.append(block)
    cursor.execute('SELECT * FROM user_files')
    user_files_data = cursor.fetchall()
    user_files = {}
    for data in user_files_data:
        if data[0] not in user_files:
            user_files[data[0]] = []
        user_files[data[0]].append(data[1])

    if user not in user_files:
        user_files[user] = []
    user_files[user].append(file.filename)
    
    block_index = len(blockchain) + 1
    previous_block = blockchain[-1] if blockchain else None
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = f'File: {file.filename}'
    hash_value = calculate_hash(block_index, previous_block.hash if previous_block else '0', timestamp, data)
    
    new_block = Block(block_index, previous_block.hash if previous_block else '0', timestamp, data, hash_value)
    blockchain.append(new_block)

    cursor.execute('DELETE FROM blockchain')
    for block in blockchain:
        cursor.execute('INSERT INTO blockchain VALUES (?, ?, ?, ?, ?)', (block.block_index, block.previous_hash, block.timestamp, block.data, block.hash))
    db.commit()

    cursor.execute('DELETE FROM user_files')
    for u, files in user_files.items():
        for file in files:
            cursor.execute('INSERT INTO user_files VALUES (?, ?)', (u, file))
    db.commit()
    
    return redirect(url_for('index'))

@app.route('/download/<file>')
def download_file(file):
    file_path = os.path.join(UPLOAD_FOLDER, file)
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    
    decrypted_data = cipher_suite.decrypt(encrypted_data)

    response = make_response(decrypted_data)
    response.headers['Content-Disposition'] = f'attachment; filename={file}'
    return response

@app.route('/delete', methods=['POST'])
def delete_file():
    if 'username' in session:
        user = session['username']
        if user not in users:
            return redirect(url_for('login'))
        filename = request.form['filename']
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM user_files WHERE username=? AND filename=?', (user, filename))
        cursor.execute('DELETE FROM blockchain WHERE data=?', (f'File: {filename}',))
        db.commit()
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
