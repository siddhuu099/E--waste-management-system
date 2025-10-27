import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from functools import wraps
from flask_mail import Mail, Message
import datetime # <-- ADDED THIS IMPORT

# --- Configuration ---
app = Flask(__name__)
app.secret_key = 'your_super_secret_key_12345'
DATABASE = 'e_waste.db'
ADMIN_EMAIL = 'admin@app.com'

# --- NEW: Flask-Mail Configuration ---
# Read email credentials from environment variables
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('E-Waste Smart', os.environ.get('MAIL_USERNAME'))

# Check if email config is missing
if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
    print("="*50)
    print("WARNING: MAIL_USERNAME or MAIL_PASSWORD environment variables not set.")
    print("Email functionality will be disabled.")
    print("Run 'export MAIL_USERNAME=your-email@gmail.com' and 'export MAIL_PASSWORD=your-app-password'")
    print("="*50)
    MAIL_ENABLED = False
else:
    MAIL_ENABLED = True
    
mail = Mail(app)


# --- Database Setup Functions ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    with app.app_context():
        db = get_db()
        # Create Users table (Simplified)
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0 
            );
        ''')
        # Create Requests table (Expanded)
        db.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- New fields from 'Request Pickup' form
                pickup_address TEXT,
                e_waste_types TEXT, -- Stored as JSON string
                estimated_weight REAL,
                pickup_date TEXT,
                pickup_time TEXT,
                phone_number TEXT,
                notes TEXT,
                
                -- New fields from 'My Pickups' UI
                estimated_value REAL DEFAULT 0,
                agent_name TEXT,
                
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        db.commit()
    print(f"Database {DATABASE} initialized and tables created.")

# Run this once to ensure the database and tables exist
init_db()

# --- Admin Decorator ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('my_pickups'))
        return f(*args, **kwargs)
    return decorated_function

# --- Utility Functions ---

def get_user_by_id(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return user

# --- MODIFIED FUNCTION ---
def get_current_user_requests(user_id):
    db = get_db()
    requests_data = db.execute(
        'SELECT * FROM requests WHERE user_id = ? ORDER BY created_at DESC', 
        (user_id,)
    ).fetchall()
    
    # Parse e_waste_types JSON
    requests_list = []
    for row in requests_data:
        req = dict(row)
        try:
            req['e_waste_types_list'] = json.loads(req['e_waste_types'])
        except:
            req['e_waste_types_list'] = [] # Handle old or invalid data
        
        # --- FIX ---
        # Convert timestamp string from SQLite into a datetime object
        # so .strftime() can be called in the template
        try:
            # SQLite format is 'YYYY-MM-DD HH:MM:SS'
            req['created_at'] = datetime.datetime.strptime(req['created_at'], '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError, AttributeError):
            # Handle cases where it might be None, already a datetime, or invalid
            pass 
        # --- END FIX ---

        requests_list.append(req)
        
    return requests_list

# --- Email Sending Functions ---

def send_email(subject, recipients, body):
    """Helper function to send emails."""
    if not MAIL_ENABLED:
        print(f"Email disabled. Would have sent email to {recipients} with subject: {subject}")
        return
    
    msg = Message(subject=subject, recipients=recipients, body=body)
    try:
        mail.send(msg)
        print(f"Successfully sent email to {recipients}")
    except Exception as e:
        print(f"Error sending email: {e}")
        pass # Don't crash the app

def send_welcome_email(user_email, user_name):
    subject = "Welcome to E-Waste Smart!"
    body = f"""
    Hi {user_name},

    Welcome to E-Waste Smart! We are so glad to have you join our company. 
    
    You're now part of a community dedicated to recycling e-waste responsibly 
    and making our planet greener.

    You can log in and request your first pickup at any time!

    Thank you,
    The E-Waste Smart Team
    """
    send_email(subject, [user_email], body)

def send_new_request_email(user_email, user_name, request_id, items):
    subject = f"We've received your pickup request #{request_id}!"
    body = f"""
    Hi {user_name},

    Thanks for doing a pickup request! We are so glad you're helping us 
    recycle responsibly.

    We have successfully received your request #{request_id} for:
    {items}

    Your request status is currently 'Pending'. We will send you another
    email as soon as an admin accepts it and schedules a pickup.

    Thank you,
    The E-Waste Smart Team
    """
    send_email(subject, [user_email], body)

def send_admin_status_update_email(user_email, user_name, request_id, new_status, items):
    subject = f"Update on Your E-Waste Request #{request_id}"
    body = f"""
    Hi {user_name},

    There's an update on your e-waste pickup request #{request_id} for:
    {items}

    New Status: {new_status}

    You can view all your requests by logging into your account.

    Thank you,
    The E-Waste Smart Team
    """
    send_email(subject, [user_email], body)


# --- Routes ---

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('my_pickups'))
    return render_template('index.html', current_page='home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('my_pickups'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        if not all([name, email, password]):
            flash('Please fill in all required fields.', 'error')
            return render_template('index.html', current_page='register')
        
        # Check if user already exists
        db = get_db()
        user_exists = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if user_exists:
            flash('Email address already registered.', 'error')
            return render_template('index.html', current_page='register')

        # Hash password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Check for admin
        is_admin = 1 if email == ADMIN_EMAIL else 0
        
        # Insert new user
        try:
            cursor = db.execute(
                'INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)',
                (name, email, hashed_password, is_admin)
            )
            db.commit()
            
            # --- MODIFIED: Send Welcome Email ---
            send_welcome_email(email, name)
            # --- End Send Email ---
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        
        except sqlite3.IntegrityError:
             flash('An error occurred. That email may already be taken.', 'error')
             return render_template('index.html', current_page='register')
        except Exception as e:
            flash(f'An unexpected error occurred: {e}', 'error')
            return render_template('index.html', current_page='register')

    # For GET request
    return render_template('index.html', current_page='register')


# --- MODIFIED: Fixed the 'login' function ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    user_id = session.get('user_id')
    if user_id:
        # If already logged in, redirect to my_pickups
        return redirect(url_for('my_pickups'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()

        if user is None:
            flash('Incorrect email or password.', 'error')
        elif not check_password_hash(user['password'], password):
            flash('Incorrect email or password.', 'error')
        else:
            # Login successful
            session.clear()
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_admin'] = user['is_admin'] == 1
            g.user = user
            flash('Logged in successfully!', 'success')
            
            if session['is_admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('my_pickups'))
        
        # --- FIX WAS HERE ---
        # If login fails, it now correctly re-renders the login page
        # to show the flash message.
        return render_template('index.html', current_page='login')

    # --- FIX WAS HERE ---
    # This handles the 'GET' request (when you first visit the page).
    # This was missing before, causing the TypeError.
    return render_template('index.html', current_page='login')

# --- FIX: Add dummy route for old dashboard link to prevent crashes ---
@app.route('/dashboard')
def dashboard():
    # Redirect any old links to /dashboard to the new /my_pickups page
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    return redirect(url_for('my_pickups'))

# --- NEW LOGGED-IN ROUTES ---

@app.route('/my_pickups')
def my_pickups():
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to view your pickups.', 'info')
        return redirect(url_for('login'))
    
    user = get_user_by_id(user_id)
    requests_data = get_current_user_requests(user_id) # <-- This now returns the corrected data
    
    # Calculate stats for the 'My Pickups' page
    stats = {
        'total_requests': len(requests_data),
        'pending': sum(1 for r in requests_data if r['status'] == 'Pending'),
        'completed': sum(1 for r in requests_data if r['status'] == 'Completed' or r['status'] == 'Recycled'),
        'total_earned': sum(r['estimated_value'] for r in requests_data if r['estimated_value'])
    }
    
    return render_template(
        'index.html', 
        current_page='my_pickups', 
        user=user, 
        requests=requests_data,
        stats=stats
    )

@app.route('/request_pickup', methods=['GET', 'POST'])
def request_pickup():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to request a pickup.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            pickup_address = request.form.get('pickup_address')
            # Get all checked e-waste types
            e_waste_types = request.form.getlist('e_waste_types')
            e_waste_types_json = json.dumps(e_waste_types)
            
            estimated_weight = request.form.get('estimated_weight')
            pickup_date = request.form.get('pickup_date')
            pickup_time = request.form.get('pickup_time')
            phone_number = request.form.get('phone_number')
            notes = request.form.get('notes')

            if not all([pickup_address, e_waste_types, estimated_weight, pickup_date, pickup_time, phone_number]):
                 flash('Please fill in all required fields.', 'error')
                 return redirect(url_for('request_pickup'))

            db = get_db()
            cursor = db.execute(
                '''INSERT INTO requests (user_id, status, pickup_address, e_waste_types, 
                                        estimated_weight, pickup_date, pickup_time, phone_number, notes) 
                   VALUES (?, 'Pending', ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, pickup_address, e_waste_types_json, estimated_weight, 
                 pickup_date, pickup_time, phone_number, notes)
            )
            db.commit()
            new_request_id = cursor.lastrowid # Get the ID of the new request
            
            # --- MODIFIED: Send New Request Email ---
            user = get_user_by_id(user_id)
            item_list_str = ", ".join(e_waste_types)
            send_new_request_email(user['email'], user['name'], new_request_id, item_list_str)
            # --- End Send Email ---
            
            flash('Pickup request submitted successfully!', 'success')
            return redirect(url_for('my_pickups'))

        except Exception as e:
            flash(f'An error occurred: {e}', 'error')
            return redirect(url_for('request_pickup'))

    user = get_user_by_id(user_id)
    return render_template(
        'index.html', 
        current_page='request_pickup',
        user=user
    )

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None) 
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# --- ADMIN ROUTES ---

@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    
    # 1. Get stats
    stats = db.execute('''
        SELECT 
            COUNT(*) as total_requests,
            SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) as pending_approval,
            SUM(estimated_weight) as total_weight,
            SUM(estimated_value) as total_value
        FROM requests
    ''').fetchone()
    
    # 2. Get all users
    all_users = db.execute('SELECT id, name, email, is_admin FROM users ORDER BY name').fetchall()
    
    # 3. Get all requests, joining with user info
    all_requests = db.execute('''
        SELECT r.*, u.name as user_name, u.email as user_email
        FROM requests r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    
    return render_template(
        'index.html', 
        current_page='admin',
        stats=dict(stats),
        all_users=[dict(row) for row in all_users],
        all_requests=[dict(row) for row in all_requests]
    )

@app.route('/admin/update_status/<int:request_id>', methods=['POST'])
@admin_required
def update_request_status(request_id):
    new_status = request.form.get('status')
    valid_statuses = ['Pending', 'Accepted', 'On the Way', 'Collected', 'Recycled', 'Cancelled']
    
    if not new_status or new_status not in valid_statuses:
        flash('Invalid status selected.', 'error')
        return redirect(url_for('admin_panel'))
    
    db = get_db()
    
    # --- Get user email/name *before* updating ---
    req_data = db.execute(
        '''SELECT u.email, u.name, r.e_waste_types 
           FROM requests r JOIN users u ON r.user_id = u.id 
           WHERE r.id = ?''', (request_id,)
    ).fetchone()

    db.execute('UPDATE requests SET status = ? WHERE id = ?', (new_status, request_id))
    db.commit()
    
    if req_data:
        try:
            item_list_str = ", ".join(json.loads(req_data['e_waste_types']))
        except:
            item_list_str = "your e-waste items"
        
        # --- MODIFIED: Call the admin update function ---
        send_admin_status_update_email(req_data['email'], req_data['name'], request_id, new_status, item_list_str)

    flash(f'Request #{request_id} status updated to {new_status}.', 'success')
    return redirect(url_for('admin_panel'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)

