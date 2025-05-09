from flask import Flask, render_template, request, redirect, session
import sqlite3
import hashlib


app = Flask(__name__)
app.secret_key = 'KEY' # weak secret key

# creating database
def init_db():
    conn = sqlite3.connect('users.db')
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
    conn.close()

# staring the program
@app.route('/')
def home():
    return redirect('/login')

# register page functions
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest() # passwords are stored using `MD5`
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')") #  direct string formatting
        conn.commit()
        conn.close()
        return redirect('/login')
    return render_template('register.html')

# login page functions
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = user[1]
            session['role'] = user[3]
            if user[3] == 'admin':
                return redirect('/admin')
            return redirect('/dashboard')
        return "Invalid credentials"
    return render_template('login.html')

# users dashboard without access control
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username, content FROM comments")
    comments = c.fetchall()
    conn.close()
    return render_template('dashboard.html', username=session['username'], comments=comments)

# admin page without access control and check
@app.route('/admin')
def admin_panel():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username, content FROM comments")
    comments = c.fetchall()
    conn.close()
    return render_template('admin.html', username=session['username'], comments=comments)

# writing comments
@app.route('/comment', methods=['POST'])
def comment():
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    content = request.form['comment'] # save content directally
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (username, content))
    conn.commit()
    conn.close()
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
