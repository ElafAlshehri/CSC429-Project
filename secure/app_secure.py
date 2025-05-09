from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
from markupsafe import escape
from dotenv import load_dotenv
import os

# using generated secret key stored in .env to make it more secure
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'users.db')

# initialize database
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            content TEXT
        )''')
        conn.commit()

@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        role = 'user' # always users, admin role is assigned manually
        try:
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed, role)) #parameterized queries
                conn.commit()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "Username already exists"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if user and bcrypt.checkpw(password, user[2]):
                session['username'] = user[1]
                session['role'] = user[3]
                if user[3] == 'admin':
                    return redirect('/admin')
                return redirect('/dashboard')
            else:
                return "Invalid credentials"
    return render_template('login.html')

# user dashboard with access control
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    if session['role'] != 'user':
        return "Access Denied"
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, content FROM comments")
    comments = c.fetchall()
    conn.close()
    return render_template('dashboard.html', username=session['username'], comments=comments)

# admin with checking roles
@app.route('/admin')
def admin_panel():
    if 'username' not in session or session['role'] != 'admin':
        return "Access Denied"
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, content FROM comments")
    comments = c.fetchall()
    conn.close()
    return render_template('admin.html', username=session['username'], comments=comments)

@app.route('/comment', methods=['POST'])
def comment():
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    content = escape(request.form['comment']) # escaped so scripts won't run.
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (username, content))
        conn.commit()
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem')) # https using self-assigned certificate
