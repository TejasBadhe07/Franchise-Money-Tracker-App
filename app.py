from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secret and unique key

DATABASE = "Empire_Hisab.db"

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
        ("user1", generate_password_hash("password1"), 0),
        ("user2", generate_password_hash("password2"), 0),
        # Add more users as needed
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
            payment_screenshot TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES login_info (id)
        )
    ''')
    conn.commit()
    conn.close()

# Ensure that both tables exist
create_login_table()
create_payment_details_table()

# Route for login
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve user information based on the given username
        cursor.execute('SELECT * FROM login_info WHERE username = ?', (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):  # Use hashed passwords
            # Authentication successful
            session['user_id'] = user[0]  # Use the user_id column as user_id
            return redirect(url_for('dashboard'))
        else:
            # Authentication failed
            return render_template('index.html', error='Invalid credentials')

    # Handle GET request, e.g., show the login form
    return render_template('index.html')

# ... (existing code)

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
            return render_template('admin_dashboard.html')
        else:
            # User role
            return render_template('user_dashboard.html', entries=entries)

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

            # Save the uploaded file to a specific folder or process it as needed
             # Get the binary data of the file
            payment_screenshot_data = payment_screenshot.read()

            conn = connect_db()
            cursor = conn.cursor()

            # Insert the payment details into the payment_details table
            cursor.execute('''
                INSERT INTO payment_details (user_id, franchise_name, user_name, utr_number, payment_screenshot)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, franchise_name, user_name, utr_number, payment_screenshot.filename))

            conn.commit()
            conn.close()

            return redirect(url_for('dashboard'))

    return render_template('upload.html')


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

        return render_template('history.html', entries=entries)

    return redirect(url_for('index'))


# Route for displaying and handling the reports section
@app.route('/reports')
def reports():
    return render_template('reports.html')


# Route for displaying and handling the reports section
@app.route('/notifications')
def notifications():
    return render_template('notifications.html')


# Route for logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
