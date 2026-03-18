import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, set_access_cookies, unset_jwt_cookies, get_jwt
)
import mysql.connector
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Secret Keys
app.secret_key = 'vox_angelos_secure_key_2026'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-vox-2026'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False 

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# File Upload Config
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database Connection
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="vox_angelos_db"
    )

# Helper function to fetch user data
def get_current_user_data(user_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    sql = "SELECT * FROM user_registration WHERE user_id = %s"
    cursor.execute(sql, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    return user

# --- CUSTOM ROLE DECORATOR ---
def roles_required(*allowed_roles):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            user_role = claims.get("role")
            if user_role in allowed_roles:
                return fn(*args, **kwargs)
            else:
                return f"Access Denied: This area is for {', '.join(allowed_roles)} only!", 403
        return decorator
    return wrapper

# --- ROUTES ---

# 1. ROOT ROUTE: Landing Page (index)
@app.route('/')
def index():
    return render_template('index.html')

# 2. LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password_candidate = request.form.get('password')

        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            sql = "SELECT * FROM user_registration WHERE user_email = %s"
            cursor.execute(sql, (email,))
            user = cursor.fetchone()
            cursor.close()
            db.close()

            if user and bcrypt.check_password_hash(user['user_password'], password_candidate):
                access_token = create_access_token(
                    identity=str(user['user_id']),
                    additional_claims={"role": user['user_role']}
                )
                
                # Role-based redirection logic
                role = user['user_role']
                if role == 'Admin':
                    resp = make_response(redirect(url_for('admin_dashboard')))
                elif role == 'LGU':
                    resp = make_response(redirect(url_for('lgu_dashboard')))
                else:
                    resp = make_response(redirect(url_for('citizen_dashboard')))
                
                set_access_cookies(resp, access_token)
                return resp
            else:
                return "Invalid email or password."
        except mysql.connector.Error as err:
            return f"Database Error: {err}"

    # If GET, show login page
    return render_template('login.html')

# 3. START REGISTRATION (Step 1)
@app.route('/signup')
def step1():
    return render_template('register.html')

# 4. PASSWORD & ID (Step 2)
@app.route('/step2', methods=['POST'])
def step2():
    data = request.form.to_dict()
    return render_template('password.html', data=data)

# 5. FINAL REGISTRATION ACTION
@app.route('/register', methods=['POST'])
def register():
    fname = request.form.get('first_name')
    mname = request.form.get('middle_name')
    lname = request.form.get('last_name')
    phone = request.form.get('phone')
    email = request.form.get('email')
    id_type = request.form.get('id_type')
    password = request.form.get('password')
    confirm_pw = request.form.get('confirm_password')

    if password != confirm_pw:
        return "Error: Passwords do not match!"

    file = request.files.get('profile_photo')
    filename = ""
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    try:
        db = get_db()
        cursor = db.cursor()
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        
        sql = """INSERT INTO user_registration 
          (user_first_name, user_middle_name, user_last_name, user_phone, user_email, user_password, user_id_type, user_id_file, user_role) 
          VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Citizen')"""

        values = (fname, mname, lname, phone, email, hashed_pw, id_type, filename)
        cursor.execute(sql, values)
        db.commit()
        cursor.close()
        db.close()
        return redirect(url_for('login'))
    except mysql.connector.Error as err:
        return f"Database Error: {err}"

# --- THREE DISTINCT DASHBOARDS ---

@app.route('/citizen/dashboard')
@roles_required('Citizen')
def citizen_dashboard():
    user_data = get_current_user_data(get_jwt_identity())
    return render_template('dashboard_citizen.html', user=user_data)

@app.route('/lgu/dashboard')
@roles_required('LGU')
def lgu_dashboard():
    user_data = get_current_user_data(get_jwt_identity())
    return render_template('dashboard_lgu.html', user=user_data)

@app.route('/admin/dashboard')
@roles_required('Admin')
def admin_dashboard():
    user_data = get_current_user_data(get_jwt_identity())
    return render_template('dashboard_admin.html', user=user_data)

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(resp)
    return resp

@jwt.unauthorized_loader
def my_unauthorized_callback(msg):
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)