from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secret and unique key

DATABASE = "Empire_Hisab.db"

# Function to connect to the SQLite database
def connect_db():
    return sqlite3.connect(DATABASE)

# Route for login
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve user information based on the given username and password
        cursor.execute('SELECT * FROM login_info WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()

        conn.close()

        if user:
            # Authentication successful
            session['user_id'] = user[2]  # Use the role column as user_id for simplicity
            return redirect(url_for('dashboard'))
        else:
            # Authentication failed
            return render_template('index.html', error='Invalid credentials')
    else:
        # Handle GET request, e.g., show the login form
        return render_template('index.html')

# Route for home/dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # User is authenticated, check role and render dashboard accordingly
        user_id = session['user_id']
        conn = connect_db()
        cursor = conn.cursor()

        # Execute a query to retrieve role information based on user_id
        cursor.execute('SELECT role FROM login_info WHERE role = ?', (user_id,))
        role = cursor.fetchone()[0]

        conn.close()

        if role == 1:
            # Admin role
            return render_template('admin_dashboard.html')
        else:
            # User role
            return render_template('user_dashboard.html')
    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('index'))

# Route for logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
