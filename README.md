# CSC429 Project: Building a Secure Web Application - Detection and Mitigation of Security Vulnerabilities

## Students:
1. Elaf Alshehri - 443200821
2. Afnan Alsuliman - 443200648
3. Najla Alharthi - 443201049
4. Ghaida Almahmoud - 443200545

## Project Structure
insecure/  
├── static/  
│   └── style.css  
├── templates/  
│   ├── admin.html  
│   ├── dashboard.html  
│   ├── login.html  
│   └── register.html  
├── app_insecure.py  
└── users.db  

secure/  
├── static/  
│   └── style.css  
├── templates/  
│   ├── admin.html  
│   ├── dashboard.html  
│   ├── login.html  
│   └── register.html  
├── .env  
├── app_secure.py  
├── cert.pem  
├── key.pem  
├── keyGenerator.py  
└── users.db  

## Overview
- insecure/app_insecure.py: A vulnerable web app containing common flaws such as:
  - SQL Injection (unsanitized SQL queries)
  - Weak password hashing (MD5)
  - Lack of role-based access control
  - XSS vulnerable

- secure/app_secure.py: A mitigated version using:
  - Prepared statements to prevent SQL injection
  - bcrypt for strong password hashing
  - Role-based access control (admin/user)
  - XSS protection using markupsafe.escape
  - HTTPS with self-signed certificates

## How to Run

### Requirements
**Install Python dependencies:**
pip install flask bcrypt python-dotenv
**Generate self-signed certificates:**
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

### Run Insecure App
cd insecure  
python app_insecure.py  
Visit: http://localhost:5000

### Run Secure App
cd secure  
python app_secure.py  
Visit: https://localhost:5000

## Security Testing Guide
**1. SQL Injection**
Login Input:
Username: ' OR '1'='1' --
Password: anything

**2. Cross-Site Scripting (XSS)**
1. Login and go to the comment form.
2. Submit: <script>alert('You have been HACKED!!')</script>

**3. Password Hashing**
- Insecure app uses MD5 (easily cracked by any cracking website like: "https://crackstation.net/").
- Secure app uses bcrypt, a slow and secure hash function with salt.

**4. Role-Based Access Control**
- Insecure app lets anyone access /admin.
- Secure app checks session ['role'] and restricts access.

## Additional Notes
- keyGenerator.py: Helper for generating strong secret Key.
- .env contains: SECRET_KEY=generated_secret_key
- Both apps use a seperate local SQLite users.db database.
- Template files (.html) exist under templates/ folders with appropriate forms for login, register, dashboard, and admin views.
