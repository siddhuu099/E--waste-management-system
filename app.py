import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from functools import wraps
import datetime 

# --- Configuration ---
app = Flask(__name__)
# YOU MUST CHANGE THIS in a real application
app.secret_key = 'your_super_secret_key_12345'
DATABASE = 'e_waste.db'
ADMIN_EMAIL = 'admin@app.com'

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
        # Create Users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0 
            );
        ''')
        # Create Requests table
        db.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                pickup_address TEXT,
                coordinates TEXT, -- For the map
                e_waste_types TEXT, -- Stored as JSON string
                estimated_weight REAL,
                pickup_date TEXT,
                pickup_time TEXT,
                phone_number TEXT,
                notes TEXT,
                
                estimated_value REAL DEFAULT 0,
                agent_name TEXT,
                
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        db.commit()
    print(f"Database {DATABASE} initialized and tables created.")

# Run this once to ensure the database and tables exist
# (You may need to run this from a Python shell: `from app import init_db; init_db()`)
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

def get_current_user_requests(user_id):
    db = get_db()
    requests_data = db.execute(
        'SELECT * FROM requests WHERE user_id = ? ORDER BY created_at DESC', 
        (user_id,)
    ).fetchall()
    
    requests_list = []
    for row in requests_data:
        req = dict(row)
        try:
            # FIX: Create the list here in Python
            req['e_waste_types_list'] = json.loads(req['e_waste_types'])
        except (json.JSONDecodeError, TypeError):
            req['e_waste_types_list'] = [] # Handle empty or invalid data
        
        try:
            req['created_at'] = datetime.datetime.strptime(req['created_at'], '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError, AttributeError):
            pass 

        requests_list.append(req)
        
    return requests_list


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
        
        db = get_db()
        user_exists = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if user_exists:
            flash('Email address already registered.', 'error')
            return render_template('index.html', current_page='register')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        # Check for admin email
        is_admin = 1 if email == ADMIN_EMAIL else 0
        
        try:
            cursor = db.execute(
                'INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)',
                (name, email, hashed_password, is_admin)
            )
            db.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        
        except sqlite3.IntegrityError:
             flash('An error occurred. That email may already be taken.', 'error')
             return render_template('index.html', current_page='register')
        except Exception as e:
            flash(f'An unexpected error occurred: {e}', 'error')
            return render_template('index.html', current_page='register')

    return render_template('index.html', current_page='register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    user_id = session.get('user_id')
    if user_id:
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
        
        return render_template('index.html', current_page='login')

    return render_template('index.html', current_page='login')

@app.route('/dashboard')
def dashboard():
    # Redirect old links to the new page
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
    requests_data = get_current_user_requests(user_id) # This list now contains 'e_waste_types_list'
    
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
            coordinates = request.form.get('coordinates') # Get map coordinates
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
                '''INSERT INTO requests (user_id, status, pickup_address, coordinates, e_waste_types, 
                                        estimated_weight, pickup_date, pickup_time, phone_number, notes) 
                   VALUES (?, 'Pending', ?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, pickup_address, coordinates, e_waste_types_json, estimated_weight, 
                 pickup_date, pickup_time, phone_number, notes)
            )
            db.commit()
            
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

@app.route('/admin_panel') # Route name matches url_for()
@admin_required
def admin_panel():
    db = get_db()
    
    # 1. Get stats
    stats_data = db.execute('''
        SELECT 
            COUNT(*) as total_requests,
            SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) as pending_approval,
            SUM(estimated_weight) as total_weight,
            SUM(estimated_value) as total_value
        FROM requests
    ''').fetchone()
    stats = dict(stats_data) if stats_data else {}
    
    # 2. Get all users
    all_users = db.execute('SELECT id, name, email, is_admin FROM users ORDER BY name').fetchall()
    
    # 3. Get all requests
    all_requests_raw = db.execute('''
        SELECT r.*, u.name as user_name, u.email as user_email
        FROM requests r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    
    # --- FIX: Process JSON in Python ---
    all_requests = []
    for row in all_requests_raw:
        req = dict(row)
        try:
            req['e_waste_types_list'] = json.loads(req['e_waste_types'])
        except (json.JSONDecodeError, TypeError):
            req['e_waste_types_list'] = [] # Handle empty or invalid data
        all_requests.append(req)
    # --- END FIX ---
    
    return render_template(
        'index.html', 
        current_page='admin',
        stats=stats,
        all_users=[dict(row) for row in all_users],
        all_requests=all_requests # Pass the processed list
    )

@app.route('/admin/update_status/<int:request_id>', methods=['POST'])
@admin_required
def update_request_status(request_id):
    new_status = request.form.get('status')
    valid_statuses = ['Pending', 'Accepted', 'On the Way', 'Completed', 'Recycled', 'Cancelled']
    
    if not new_status or new_status not in valid_statuses:
        flash('Invalid status selected.', 'error')
        return redirect(url_for('admin_panel'))
    
    db = get_db()
    db.execute('UPDATE requests SET status = ? WHERE id = ?', (new_status, request_id))
    db.commit()

    flash(f'Request #{request_id} status updated to {new_status}.', 'success')
    return redirect(url_for('admin_panel'))

# Run the app
if __name__ == '__main__':
    # Important: Delete your old 'e_waste.db' file before running
    # this for the first time so the 'coordinates' column is added.
    app.run(debug=True)
    
