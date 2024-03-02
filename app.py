from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secret and unique key

DATABASE = "Empire_Hisab.db"
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to connect to the SQLite database
def connect_db():
    return sqlite3.connect(DATABASE)

# Create a table for login information
def create_login_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role INTEGER NOT NULL
        )
    ''')

    # Insert predefined users with hashed passwords
    predefined_users = [
        ("admin", generate_password_hash("admin_password"), 1),  # Admin role
        ("user", generate_password_hash("user_password"), 0),  # User role
    ]

    cursor.executemany('INSERT INTO login_info (username, password, role) VALUES (?, ?, ?)', predefined_users)

    conn.commit()
    conn.close()

# Create a table for payment details
def create_payment_details_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payment_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            franchise_name TEXT NOT NULL,
            user_name TEXT NOT NULL,
            utr_number TEXT NOT NULL,
            payment_screenshot_path TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES login_info (id)
        )
    ''')
    conn.commit()
    conn.close()

# Ensure that both tables exist
create_login_table()
create_payment_details_table()

# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for login
@app.route('/', methods=['GET', 'POST'])
def index():
    error_message = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        selected_role = int(request.form['role'])

        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve user information based on the given username
        cursor.execute('SELECT * FROM login_info WHERE username = ?', (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password) and user[3] == selected_role:
            # Authentication successful
            session['user_id'] = user[0]  # Use the user_id column as user_id
            session['role'] = selected_role  # Store the selected role in the session
            return redirect(url_for('dashboard'))
        else:
            # Authentication failed
            error_message = 'Invalid credentials. Please check your username, password, and role.'

    # Handle GET request, e.g., show the login form
    return render_template('index.html', error=error_message)

# Route for home/dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # User is authenticated, check role and render dashboard accordingly
        user_id = session['user_id']
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
        role = cursor.fetchone()[0]

        # Retrieve payment details for the logged-in user
        cursor.execute('SELECT * FROM payment_details WHERE user_id = ?', (user_id,))
        entries = cursor.fetchall()

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin/admin_dashboard.html', entries=entries)
        else:
            # User role
            return render_template('user/user_dashboard.html', entries=entries)

    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('index'))

# Route for displaying and handling the form to upload payment details
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        user_id = session.get('user_id')
        if user_id:
            franchise_name = request.form['franchiseName']
            user_name = request.form['userName']
            utr_number = request.form['utrNumber']

            # Use request.files to get the uploaded file
            payment_screenshot = request.files['paymentScreenshot']

            if payment_screenshot and allowed_file(payment_screenshot.filename):
                # Save the uploaded file to the uploads folder
                filename = os.path.join(app.config['UPLOAD_FOLDER'], payment_screenshot.filename)
                payment_screenshot.save(filename)

                conn = connect_db()
                cursor = conn.cursor()

                # Insert the payment details into the payment_details table
                cursor.execute('''
                    INSERT INTO payment_details (user_id, franchise_name, user_name, utr_number, payment_screenshot_path)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, franchise_name, user_name, utr_number, filename))

                conn.commit()
                conn.close()

                # Check the role of the logged-in user
                conn = connect_db()
                cursor = conn.cursor()

                # Execute a query to retrieve role information based on user_id
                cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
                role = cursor.fetchone()[0]

                conn.close()

                if role == 1:
                    # Admin role
                    return render_template('admin/admin_upload.html')
                else:
                    # User role
                    return render_template('user/user_upload.html')

    # Default to admin or user upload form based on the logged-in user's role
    user_id = session.get('user_id')
    if user_id:
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
        role = cursor.fetchone()[0]

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin/admin_upload.html')
        else:
            # User role
            return render_template('user/user_upload.html')

    return redirect(url_for('index'))  # Redirect to login if not logged in

# Route for displaying payment history
@app.route('/history')
def history():
    user_id = session.get('user_id')
    if user_id:
        conn = connect_db()
        cursor = conn.cursor()

        # Retrieve all columns for the logged-in user
        cursor.execute('SELECT * FROM payment_details WHERE user_id = ?', (user_id,))
        entries = cursor.fetchall()

        conn.close()

        if 'role' in session and session['role'] == 1:
            # Admin role
            # Retrieve all payment details for all users (for admin view)
            cursor = connect_db().cursor()
            cursor.execute('SELECT * FROM payment_details')
            all_entries = cursor.fetchall()

            return render_template('admin/admin_history.html', entries=all_entries)
        else:
            # Redirect regular users to the dashboard (or another appropriate page)
            return redirect(url_for('dashboard'))

    return redirect(url_for('index'))


# Route for displaying and handling the reports section
@app.route('/reports')
def reports():
    if 'user_id' in session:
        # User is authenticated, check role and render reports accordingly
        user_id = session['user_id']
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
        role = cursor.fetchone()[0]

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin/admin_reports.html')
        else:
            # User role
            return render_template('user/user_reports.html')

    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('index'))

# Route for displaying and handling the notifications section
@app.route('/notifications')
def notifications():
    # Check the role of the logged-in user
    user_id = session.get('user_id')
    if user_id:
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
        role = cursor.fetchone()[0]

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin/admin_notifications.html')
        else:
            # User role
            return render_template('user/user_notifications.html')

    return redirect(url_for('index'))  # Redirect to login if not logged in

# Route for logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)



"""from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secret and unique key

DATABASE = "Empire_Hisab.db"
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to connect to the SQLite database
def connect_db():
    return sqlite3.connect(DATABASE)

# Create a table for login information
def create_login_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role INTEGER NOT NULL
        )
    ''')

    # Insert predefined users with hashed passwords
    predefined_users = [
        ("admin", generate_password_hash("admin_password"), 1),  # Admin role
        ("user", generate_password_hash("user_password"), 0),    # User role
    ]

    cursor.executemany('INSERT INTO login_info (username, password, role) VALUES (?, ?, ?)', predefined_users)

    conn.commit()
    conn.close()

# Create a table for payment details
def create_payment_details_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payment_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            franchise_name TEXT NOT NULL,
            user_name TEXT NOT NULL,
            utr_number TEXT NOT NULL,
            payment_screenshot_path TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES login_info (id)
        )
    ''')
    conn.commit()
    conn.close()

# Ensure that both tables exist
create_login_table()
create_payment_details_table()

# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for login
@app.route('/', methods=['GET', 'POST'])
def index():
    error_message = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        selected_role = int(request.form['role'])


        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve user information based on the given username
        cursor.execute('SELECT * FROM login_info WHERE username = ?', (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password) and user[3] == selected_role:
            # Authentication successful
            session['user_id'] = user[0]  # Use the user_id column as user_id
            session['role'] = selected_role  # Store the selected role in the session
            return redirect(url_for('dashboard'))
        else:
            # Authentication failed
            error_message = 'Invalid credentials. Please check your username, password, and role.'

    # Handle GET request, e.g., show the login form
    return render_template('index.html', error=error_message)

# Route for home/dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # User is authenticated, check role and render dashboard accordingly
        user_id = session['user_id']
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
        role = cursor.fetchone()[0]

        # Retrieve payment details for the logged-in user
        cursor.execute('SELECT * FROM payment_details WHERE user_id = ?', (user_id,))
        entries = cursor.fetchall()

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin/admin_dashboard.html', entries=entries)
        else:
            # User role
            return render_template('user/user_dashboard.html', entries=entries)

    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('index'))
    
    
# Route for displaying and handling the form to upload payment details
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        user_id = session.get('user_id')
        if user_id:
            franchise_name = request.form['franchiseName']
            user_name = request.form['userName']
            utr_number = request.form['utrNumber']

            # Use request.files to get the uploaded file
            payment_screenshot = request.files['paymentScreenshot']

            if payment_screenshot and allowed_file(payment_screenshot.filename):
                # Save the uploaded file to the uploads folder
                filename = os.path.join(app.config['UPLOAD_FOLDER'], payment_screenshot.filename)
                payment_screenshot.save(filename)

                conn = connect_db()
                cursor = conn.cursor()

                # Insert the payment details into the payment_details table
                cursor.execute('''
                    INSERT INTO payment_details (user_id, franchise_name, user_name, utr_number, payment_screenshot_path)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, franchise_name, user_name, utr_number, filename))

                conn.commit()
                conn.close()

                # Check the role of the logged-in user
                conn = connect_db()
                cursor = conn.cursor()

                # Execute a query to retrieve role information based on user_id
                cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
                role = cursor.fetchone()[0]

                conn.close()

                if role == 1:
                    # Admin role
                    return render_template('admin/admin_upload.html')
                else:
                    # User role
                    return render_template('user/user_upload.html')

    # Default to admin or user upload form based on the logged-in user's role
    user_id = session.get('user_id')
    if user_id:
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
        role = cursor.fetchone()[0]

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin/admin_upload.html')
        else:
            # User role
            return render_template('user/user_upload.html')

    return redirect(url_for('index'))  # Redirect to login if not logged in



# Route to serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Route for displaying payment history
@app.route('/history')
def history():
    user_id = session.get('user_id')
    if user_id:
        conn = connect_db()
        cursor = conn.cursor()

        # Retrieve all columns for the logged-in user
        cursor.execute('SELECT * FROM payment_details WHERE user_id = ?', (user_id,))
        entries = cursor.fetchall()

        conn.close()

        return render_template('admin/admin_history.html', entries=entries)

    return redirect(url_for('index'))

# Route for displaying and handling the reports section
@app.route('/reports')
def reports():
    if 'user_id' in session:
        # User is authenticated, check role and render reports accordingly
        user_id = session['user_id']
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
        role = cursor.fetchone()[0]

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin/admin_reports.html')
        else:
            # User role
            return render_template('user/user_reports.html')

    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('index'))

# Route for displaying and handling the notifications section
@app.route('/notifications')
def notifications():
    # Check the role of the logged-in user
    user_id = session.get('user_id')
    if user_id:
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE id = ?', (user_id,))
        role = cursor.fetchone()[0]

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin/admin_notifications.html')
        else:
            # User role
            return render_template('user/user_notifications.html')

    return redirect(url_for('index'))  # Redirect to login if not logged in


# Route for logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
"""