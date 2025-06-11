from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, send_from_directory, session, Response
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
import os
# Ensure 'logs' directory exists before logging setup
os.makedirs('logs', exist_ok=True)
import logging
import sqlite3
import hashlib
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from zoho_fixed import BulkMailer
from markupsafe import Markup
from functools import wraps

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# Initialize Flask app
app = Flask(__name__)

# Use development config by default
config_name = os.environ.get('FLASK_ENV', 'development')
if config_name == 'production':
    app.config.from_object('config.ProductionConfig')
elif config_name == 'testing':
    app.config.from_object('config.TestingConfig')
else:
    app.config.from_object('config.DevelopmentConfig')

# CRITICAL: Add static file configuration for production
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files explicitly"""
    return send_from_directory('static', filename)

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

# Add CSP headers to allow external resources
@app.after_request
def after_request(response):
    # Allow external CSS/JS resources
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    return response

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)

# Ensure required directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static', exist_ok=True)

# Database initialization
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            plan TEXT NOT NULL DEFAULT 'free',
            emails_sent_today INTEGER DEFAULT 0,
            last_reset_date TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Email logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            recipient_count INTEGER,
            subject TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Upgrade requests table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS upgrade_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            requested_plan TEXT NOT NULL,
            transaction_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Subscription plans
PLANS = {
    'free': {
        'name': 'Free Plan',
        'price': 0,
        'daily_limit': 5,
        'features': ['Basic email sending', 'CSV upload', 'Standard templates']
    },
    'basic': {
        'name': 'Basic Plan',
        'price': 2000,
        'daily_limit': 200,
        'features': ['Everything in Free', 'Priority support', 'Custom templates', 'Advanced personalization']
    },
    'professional': {
        'name': 'Professional Plan', 
        'price': 3000,
        'daily_limit': 500,
        'features': ['Everything in Basic', 'Email analytics', 'A/B testing', 'Custom CSS support', 'Dedicated support']
    },
    'enterprise': {
        'name': 'Enterprise Plan',
        'price': 5000,
        'daily_limit': 1000,
        'features': ['Everything in Professional', 'White-label solution', 'API access', 'Custom integrations', '24/7 phone support']
    }
}

# Authentication helpers
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hash_value):
    """Verify password against hash"""
    return hash_password(password) == hash_value

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this feature.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_info(user_id):
    """Get user information from database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'email': user[1],
            'full_name': user[3],
            'plan': user[4],
            'emails_sent_today': user[5],
            'last_reset_date': user[6]
        }
    return None

def reset_daily_email_count():
    """Reset daily email count if needed"""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users 
        SET emails_sent_today = 0, last_reset_date = ? 
        WHERE last_reset_date != ? OR last_reset_date = ''
    ''', (today, today))
    conn.commit()
    conn.close()

def check_email_limit(user_id):
    """Check if user can send more emails today"""
    reset_daily_email_count()
    user = get_user_info(user_id)
    if not user:
        return False, 0, 0
    
    plan = PLANS.get(user['plan'], PLANS['free'])
    daily_limit = plan['daily_limit']
    sent_today = user['emails_sent_today']
    
    return sent_today < daily_limit, sent_today, daily_limit

def update_email_count(user_id, count):
    """Update user's email count"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users 
        SET emails_sent_today = emails_sent_today + ? 
        WHERE id = ?
    ''', (count, user_id))
    conn.commit()
    conn.close()

def log_email_send(user_id, recipient_count, subject):
    """Log email send to database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO email_logs (user_id, recipient_count, subject)
        VALUES (?, ?, ?)
    ''', (user_id, recipient_count, subject))
    conn.commit()
    conn.close()

# Forms
class SignupForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)],
                           render_kw={"placeholder": "Enter your full name"})
    email = StringField('Email Address', validators=[DataRequired(), Email()],
                       render_kw={"placeholder": "your-email@company.com"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)],
                           render_kw={"placeholder": "Choose a strong password"})
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password', message='Passwords must match')],
                                   render_kw={"placeholder": "Confirm your password"})
    plan = SelectField('Choose Plan', choices=[
        ('free', 'Free Plan - 15 emails/day (₹0)'),
        ('basic', 'Basic Plan - 200 emails/day (₹2,000)'),
        ('professional', 'Professional Plan - 500 emails/day (₹3,000)'),
        ('enterprise', 'Enterprise Plan - 1000 emails/day (₹5,000)')
    ], default='free')

class LoginForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Email()],
                       render_kw={"placeholder": "your-email@company.com"})
    password = PasswordField('Password', validators=[DataRequired()],
                           render_kw={"placeholder": "Enter your password"})

class BulkMailForm(FlaskForm):
    email = StringField('Zoho Email', validators=[DataRequired(), Email()], 
                       render_kw={"placeholder": "your-email@zoho.com"})
    password = PasswordField('Zoho Password', validators=[DataRequired()],
                           render_kw={"placeholder": "Your Zoho app password"})
    subject = StringField('Email Subject', validators=[DataRequired()],
                         render_kw={"placeholder": "Enter email subject"})
    body = TextAreaField('Email Body', validators=[DataRequired()],
                        render_kw={"rows": 8, "placeholder": "Email content will be captured from rich text editor"})
    email_list = FileField('Email List (CSV)', validators=[
        FileRequired(),
        FileAllowed(['csv'], 'Only CSV files are allowed!')
    ])
    document = FileField('Document Attachment (Optional)', validators=[
        FileAllowed(['pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'], 
                   'Only PDF, Word, PowerPoint, and Excel files are allowed!')
    ])
    smtp_provider = SelectField('SMTP Provider', choices=[
        ('auto', 'Auto (Detect from Email)'),
        ('zoho', 'Zoho'),
        ('gmail', 'Gmail/Google Workspace'),
        ('outlook', 'Outlook/Office365'),
        ('ses', 'Amazon SES'),
        ('sendgrid', 'SendGrid'),
        ('mailgun', 'Mailgun'),
        ('custom', 'Custom SMTP')
    ], default='auto', render_kw={"class": "form-select"})
    smtp_server = StringField('SMTP Server', render_kw={"placeholder": "smtp.example.com", "class": "form-control"})
    smtp_port = StringField('SMTP Port', render_kw={"placeholder": "587", "class": "form-control"})

# Routes
@app.route('/')
def home():
    """Landing page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html', plans=PLANS)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration"""
    form = SignupForm()
    if form.validate_on_submit():
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            # Check if email already exists
            cursor.execute('SELECT id FROM users WHERE email = ?', (form.email.data,))
            if cursor.fetchone():
                flash('Email already registered. Please use a different email or log in.', 'error')
                return render_template('signup.html', form=form, plans=PLANS)
            # Insert new user with free plan only
            password_hash = hash_password(form.password.data)
            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute('''
                INSERT INTO users (email, password_hash, full_name, plan, last_reset_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (form.email.data, password_hash, form.full_name.data, 'free', today))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            # Log user in
            session['user_id'] = user_id
            session['user_email'] = form.email.data
            session['user_name'] = form.full_name.data
            session['user_plan'] = 'free'
            # If user selected a premium plan, store in session and redirect to payment
            if form.plan.data != 'free':
                session['pending_upgrade_plan'] = form.plan.data
                flash('Account created! Please complete payment to activate your selected plan.', 'info')
                return redirect(url_for('signup_payment'))
            flash(f'Welcome to Dazzlo! Your Free Plan account has been created.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            app.logger.error(f"Signup error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
    return render_template('signup.html', form=form, plans=PLANS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    form = LoginForm()
    if form.validate_on_submit():
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ? AND is_active = 1', (form.email.data,))
            user = cursor.fetchone()
            conn.close()
            
            if user and verify_password(form.password.data, user[2]):
                session['user_id'] = user[0]
                session['user_email'] = user[1]
                session['user_name'] = user[3]
                session['user_plan'] = user[4]
                
                flash(f'Welcome back, {user[3]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'error')
                
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = get_user_info(session['user_id'])
    can_send, sent_today, daily_limit = check_email_limit(session['user_id'])
    
    # Get recent email logs
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT recipient_count, subject, sent_at 
        FROM email_logs 
        WHERE user_id = ? 
        ORDER BY sent_at DESC 
        LIMIT 5
    ''', (session['user_id'],))
    recent_emails = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', 
                         user=user, 
                         plan_info=PLANS[user['plan']],
                         sent_today=sent_today,
                         daily_limit=daily_limit,
                         can_send=can_send,
                         recent_emails=recent_emails)

@app.route('/bulk-mail', methods=['GET', 'POST'])
@login_required
def bulk_mail():
    """Main bulk mail sending interface"""
    user = get_user_info(session['user_id'])
    can_send, sent_today, daily_limit = check_email_limit(session['user_id'])
    
    if not can_send:
        flash(f'Daily email limit reached ({daily_limit} emails). Upgrade your plan for higher limits.', 'warning')
        return redirect(url_for('dashboard'))
    
    form = BulkMailForm()
    if form.validate_on_submit():
        email_list_path = None
        document_path = None
        try:
            app.logger.info(f"Bulk mail request from {form.email.data}")
            
            # Get HTML content from form
            email_body_html = form.body.data
            
            # Debug logging
            app.logger.info(f"Email body type: {type(email_body_html)}")
            app.logger.info(f"Email body preview: {email_body_html[:200]}...")
            
            if hasattr(email_body_html, '__html__'):
                email_body_html = str(email_body_html)
            
            if not email_body_html or email_body_html.strip() == '':
                flash('Email body cannot be empty!', 'error')
                return redirect(url_for('bulk_mail'))
            
            # Save uploaded files
            email_list_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                secure_filename(form.email_list.data.filename)
            )
            form.email_list.data.save(email_list_path)
            
            # Handle document attachment
            if form.document.data:
                document_path = os.path.join(
                    app.config['UPLOAD_FOLDER'],
                    secure_filename(form.document.data.filename)
                )
                form.document.data.save(document_path)
            
            # Initialize mailer with custom SMTP if provided
            smtp_server = form.smtp_server.data.strip() if form.smtp_server.data else None
            smtp_port = int(form.smtp_port.data.strip()) if form.smtp_port.data else None
            if form.smtp_provider.data == 'custom' and smtp_server and smtp_port:
                mailer = BulkMailer(
                    email=form.email.data,
                    password=form.password.data,
                    smtp_server=smtp_server,
                    smtp_port=smtp_port
                )
            else:
                mailer = BulkMailer(
                    email=form.email.data,
                    password=form.password.data
                )
            
            # Read recipients
            recipients = mailer.read_emails_from_csv(email_list_path)
            
            if not recipients:
                flash('No valid email addresses found in the CSV file!', 'error')
                cleanup_files([email_list_path, document_path])
                return redirect(url_for('bulk_mail'))
            
            # Check email limit
            remaining_limit = daily_limit - sent_today
            if len(recipients) > remaining_limit:
                flash(f'Cannot send {len(recipients)} emails. Daily limit allows {remaining_limit} more emails today.', 'error')
                cleanup_files([email_list_path, document_path])
                return redirect(url_for('bulk_mail'))
            
            print(f"DEBUG: Sending emails to {len(recipients)} recipients")
            
            # Send emails
            success_count = mailer.send_bulk_emails(
                recipients=recipients,
                subject=form.subject.data,
                body=email_body_html,
                attachment_path=document_path
            )
            
            # Update user's email count
            update_email_count(session['user_id'], success_count)
            log_email_send(session['user_id'], success_count, form.subject.data)
            
            flash(f'Successfully sent emails to {success_count} recipients!', 'success')
            app.logger.info(f"Successfully sent {success_count} emails")
            
            # Cleanup uploaded files
            cleanup_files([email_list_path, document_path])
            
            return render_template('success.html', count=success_count, user=user)
            
        except Exception as e:
            app.logger.error(f"Error in bulk mail: {str(e)}")
            flash(f'Error: {str(e)}', 'error')
            cleanup_files([email_list_path, document_path])
            return redirect(url_for('bulk_mail'))
    
    return render_template('bulk_mail.html', form=form, user=user, plan_info=PLANS[user['plan']])

@app.route('/api/validate-email', methods=['POST'])
@login_required
def validate_email():
    """API endpoint to validate email credentials"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        smtp_server = data.get('smtp_server')
        smtp_port = data.get('smtp_port')
        
        if not email or not password:
            return jsonify({'valid': False, 'message': 'Email and password required'})
        
        try:
            if smtp_server and smtp_port:
                mailer = BulkMailer(email=email, password=password, smtp_server=smtp_server, smtp_port=int(smtp_port))
            else:
                mailer = BulkMailer(email=email, password=password)
            mailer.test_connection()
            return jsonify({'valid': True, 'message': 'Credentials validated successfully'})
        except Exception as e:
            return jsonify({'valid': False, 'message': f'Invalid credentials: {str(e)}'})
    
    except Exception as e:
        return jsonify({'valid': False, 'message': str(e)})

@app.route('/upgrade')
@login_required  
def upgrade():
    """Upgrade plan page"""
    user = get_user_info(session['user_id'])
    return render_template('upgrade.html', user=user, plans=PLANS, current_plan=user['plan'])

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0'
    })

@app.route('/activate-plan', methods=['POST'])
@login_required
def activate_plan():
    """Activate a new plan for the user after payment confirmation."""
    plan_id = request.json.get('plan_id')
    if plan_id not in PLANS:
        return jsonify({'success': False, 'message': 'Invalid plan selected.'}), 400
    user_id = session['user_id']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET plan = ? WHERE id = ?', (plan_id, user_id))
    conn.commit()
    conn.close()
    session['user_plan'] = plan_id
    return jsonify({'success': True, 'message': f'Plan upgraded to {PLANS[plan_id]["name"]}.'})

@app.route('/request-upgrade', methods=['POST'])
@login_required
def request_upgrade():
    data = request.get_json()
    plan_id = data.get('plan_id')
    transaction_id = data.get('transaction_id', '').strip()
    if plan_id not in PLANS:
        return jsonify({'success': False, 'message': 'Invalid plan selected.'}), 400
    if not transaction_id:
        return jsonify({'success': False, 'message': 'Transaction ID is required.'}), 400
    user_id = session['user_id']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Prevent duplicate pending requests for the same user and plan
    cursor.execute('SELECT id FROM upgrade_requests WHERE user_id = ? AND requested_plan = ? AND status = "pending"', (user_id, plan_id))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'You already have a pending upgrade request for this plan.'}), 400
    cursor.execute('INSERT INTO upgrade_requests (user_id, requested_plan, transaction_id, status) VALUES (?, ?, ?, ?)',
                   (user_id, plan_id, transaction_id, 'pending'))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Upgrade request submitted! An admin will review and approve your upgrade soon.'})

@app.route('/admin/upgrades', methods=['GET', 'POST'])
def admin_upgrades():
    # Admin login via login page section
    if 'admin_logged_in' not in session:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            if username == 'admin' and password == 'admin5503':
                session['admin_logged_in'] = True
                return redirect(url_for('admin_upgrades'))
            else:
                flash('Incorrect admin credentials.', 'error')
                return redirect(url_for('login'))
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    if request.method == 'POST' and 'approve_id' in request.form:
        req_id = request.form['approve_id']
        # Get request details
        cursor.execute('SELECT user_id, requested_plan FROM upgrade_requests WHERE id = ? AND status = "pending"', (req_id,))
        row = cursor.fetchone()
        if row:
            user_id, plan_id = row
            # Update user plan
            cursor.execute('UPDATE users SET plan = ? WHERE id = ?', (plan_id, user_id))
            # Mark request as approved
            cursor.execute('UPDATE upgrade_requests SET status = "approved" WHERE id = ?', (req_id,))
            conn.commit()
            flash('Upgrade approved and plan activated!', 'success')
    # Get all pending requests
    cursor.execute('''
        SELECT ur.id, u.email, ur.requested_plan, ur.transaction_id, ur.status, ur.created_at
        FROM upgrade_requests ur
        JOIN users u ON ur.user_id = u.id
        WHERE ur.status = "pending"
        ORDER BY ur.created_at DESC
    ''')
    requests = cursor.fetchall()
    conn.close()
    return render_template('admin_upgrades.html', requests=requests, plans=PLANS)

@app.route('/signup-payment', methods=['GET', 'POST'])
def signup_payment():
    if 'pending_upgrade_plan' not in session:
        return redirect(url_for('dashboard'))
    plan_id = session['pending_upgrade_plan']
    plan = PLANS.get(plan_id)
    if not plan or plan_id == 'free':
        return redirect(url_for('dashboard'))
    # Render a payment page similar to the upgrade modal
    if request.method == 'POST':
        txn_id = request.form.get('transaction_id', '').strip()
        if not txn_id:
            flash('Please enter your UPI transaction ID.', 'error')
        else:
            # Create a pending upgrade request
            user_id = session['user_id']
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM upgrade_requests WHERE user_id = ? AND requested_plan = ? AND status = "pending"', (user_id, plan_id))
            if cursor.fetchone():
                conn.close()
                flash('You already have a pending upgrade request for this plan.', 'warning')
                return redirect(url_for('dashboard'))
            cursor.execute('INSERT INTO upgrade_requests (user_id, requested_plan, transaction_id, status) VALUES (?, ?, ?, ?)',
                           (user_id, plan_id, txn_id, 'pending'))
            conn.commit()
            conn.close()
            session.pop('pending_upgrade_plan', None)
            flash('Upgrade request submitted! An admin will review and approve your upgrade soon.', 'success')
            return redirect(url_for('dashboard'))
    return render_template('signup_payment.html', plan=plan, plan_id=plan_id)

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(413)
def too_large(error):
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(url_for('bulk_mail'))

def cleanup_files(file_paths):
    """Helper function to cleanup uploaded files"""
    for file_path in file_paths:
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                app.logger.info(f"Cleaned up file: {file_path}")
            except Exception as e:
                app.logger.error(f"Error cleaning up file {file_path}: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)