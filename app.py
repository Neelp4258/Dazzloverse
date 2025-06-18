#!/usr/bin/env python3
"""
DazzloGo - Professional Bulk Email Platform
Flask Web Application with Advanced SMTP Integration
"""

import os
import csv
import sqlite3
import hashlib
import json
import tempfile
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, PasswordField, SelectField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formataddr
import threading
import socket

# Import our advanced bulk emailer
import sys
sys.path.append('.')

# Recreate the advanced emailer classes inline for integration
class AdvancedSMTPMailer:
    """Integrated SMTP mailer for DazzloGo"""
    
    def __init__(self, email: str, password: str, smtp_server: str = None, smtp_port: int = None):
        self.email = email.strip()
        self.password = password
        self.domain = email.split('@')[-1].lower()
        
        # Store custom SMTP if provided
        self.custom_smtp_server = smtp_server
        self.custom_smtp_port = smtp_port
        
        # Working configuration
        self.working_config = None
        
        # Statistics
        self.stats = {
            'total_emails': 0,
            'successful_sends': 0,
            'failed_sends': 0,
            'start_time': None,
            'end_time': None
        }
    
    def get_smtp_configs(self):
        """Get SMTP configurations for testing"""
        configs = []
        
        # Custom SMTP first if provided
        if self.custom_smtp_server and self.custom_smtp_port:
            configs.extend([
                (self.custom_smtp_server, self.custom_smtp_port, False, 'STARTTLS'),
                (self.custom_smtp_server, self.custom_smtp_port, True, 'SSL'),
            ])
        
        # Domain-specific configurations
        if 'zoho' in self.domain or self.domain.endswith('.in'):
            configs.extend([
                ("smtp.zoho.in", 587, False, 'STARTTLS'),
                ("smtp.zoho.com", 587, False, 'STARTTLS'),
                ("smtp.zoho.in", 465, True, 'SSL'),
                ("smtp.zoho.com", 465, True, 'SSL'),
            ])
        elif 'gmail' in self.domain:
            configs.extend([
                ("smtp.gmail.com", 587, False, 'STARTTLS'),
                ("smtp.gmail.com", 465, True, 'SSL'),
            ])
        elif any(x in self.domain for x in ['outlook', 'hotmail', 'live']):
            configs.extend([
                ("smtp.office365.com", 587, False, 'STARTTLS'),
                ("smtp.live.com", 587, False, 'STARTTLS'),
            ])
        else:
            # Generic configurations
            configs.extend([
                (f"smtp.{self.domain}", 587, False, 'STARTTLS'),
                (f"mail.{self.domain}", 587, False, 'STARTTLS'),
                ("smtp.zoho.in", 587, False, 'STARTTLS'),
                ("smtp.gmail.com", 587, False, 'STARTTLS'),
            ])
        
        return configs
    
    def test_connection(self) -> dict:
        """Test SMTP connection and return result"""
        configs = self.get_smtp_configs()
        
        for server, port, use_ssl, protocol in configs:
            try:
                if use_ssl:
                    context = ssl.create_default_context()
                    smtp_server = smtplib.SMTP_SSL(server, port, timeout=10, context=context)
                else:
                    smtp_server = smtplib.SMTP(server, port, timeout=10)
                    smtp_server.ehlo()
                    if smtp_server.has_extn('STARTTLS'):
                        smtp_server.starttls()
                        smtp_server.ehlo()
                
                # Test authentication
                smtp_server.login(self.email, self.password)
                smtp_server.quit()
                
                # Store working configuration
                self.working_config = (server, port, use_ssl, protocol)
                
                return {
                    'success': True,
                    'server': server,
                    'port': port,
                    'protocol': protocol
                }
                
            except Exception as e:
                continue
        
        return {
            'success': False,
            'error': 'Could not connect with any SMTP configuration'
        }
    
    def create_smtp_connection(self):
        """Create SMTP connection using working configuration"""
        if not self.working_config:
            test_result = self.test_connection()
            if not test_result['success']:
                raise Exception(test_result['error'])
        
        server, port, use_ssl, protocol = self.working_config
        
        try:
            if use_ssl:
                context = ssl.create_default_context()
                smtp_server = smtplib.SMTP_SSL(server, port, timeout=30, context=context)
            else:
                smtp_server = smtplib.SMTP(server, port, timeout=30)
                smtp_server.ehlo()
                if smtp_server.has_extn('STARTTLS'):
                    smtp_server.starttls()
                    smtp_server.ehlo()
            
            smtp_server.login(self.email, self.password)
            return smtp_server
            
        except Exception as e:
            raise Exception(f"Failed to create SMTP connection: {e}")
    
    def send_bulk_emails(self, recipients: list, subject: str, body: str, 
                        attachment_path: str = None) -> dict:
        """Send bulk emails to recipients"""
        
        self.stats = {
            'total_emails': len(recipients),
            'successful_sends': 0,
            'failed_sends': 0,
            'start_time': datetime.now(),
            'end_time': None,
            'failed_recipients': []
        }
        
        try:
            smtp_server = self.create_smtp_connection()
            
            for i, recipient in enumerate(recipients, 1):
                try:
                    # Create message
                    msg = MIMEMultipart()
                    
                    # Headers
                    sender_name = self.email.split('@')[0].replace('.', ' ').title()
                    msg['From'] = formataddr((sender_name, self.email))
                    msg['To'] = recipient['email']
                    msg['Subject'] = subject
                    
                    # Personalize body
                    personalized_body = body
                    for key, value in recipient.items():
                        personalized_body = personalized_body.replace(f'{{{key}}}', value or '')
                    
                    # Add body
                    if '<html>' in personalized_body.lower() or '<p>' in personalized_body.lower():
                        msg.attach(MIMEText(personalized_body, 'html', 'utf-8'))
                    else:
                        msg.attach(MIMEText(personalized_body, 'plain', 'utf-8'))
                    
                    # Add attachment if provided
                    if attachment_path and os.path.exists(attachment_path):
                        try:
                            with open(attachment_path, 'rb') as attachment:
                                part = MIMEBase('application', 'octet-stream')
                                part.set_payload(attachment.read())
                            
                            encoders.encode_base64(part)
                            filename = os.path.basename(attachment_path)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= "{filename}"'
                            )
                            msg.attach(part)
                        except Exception as e:
                            print(f"Error attaching file: {e}")
                    
                    # Send email
                    smtp_server.send_message(msg)
                    self.stats['successful_sends'] += 1
                    
                    # Small delay to avoid being flagged as spam
                    time.sleep(1)
                    
                except Exception as e:
                    self.stats['failed_sends'] += 1
                    self.stats['failed_recipients'].append({
                        'email': recipient['email'],
                        'error': str(e)
                    })
            
            smtp_server.quit()
            
        except Exception as e:
            raise Exception(f"SMTP connection error: {e}")
        
        self.stats['end_time'] = datetime.now()
        return self.stats

# Flask Application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dazzlego-secret-key-2025'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Setup logging
def setup_logging():
    """Setup comprehensive logging for the application"""
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    app_logger = logging.getLogger('dazzlego')
    app_logger.setLevel(logging.INFO)
    
    log_file = os.path.join(log_dir, f'app_{datetime.now().strftime("%Y%m%d")}.log')
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    app_logger.addHandler(file_handler)
    app_logger.addHandler(console_handler)
    
    return app_logger

app_logger = setup_logging()

# Database initialization
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect('dazzlego.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            contact_number TEXT,
            password_hash TEXT NOT NULL,
            plan TEXT DEFAULT 'free',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            emails_sent_today INTEGER DEFAULT 0,
            last_email_date DATE DEFAULT CURRENT_DATE
        )
    ''')
    
    # Email campaigns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            subject TEXT NOT NULL,
            recipient_count INTEGER NOT NULL,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Upgrade requests table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS upgrade_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            requested_plan TEXT NOT NULL,
            transaction_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Plans configuration
PLANS = {
    'free': {
        'name': 'Free',
        'price': 0,
        'daily_limit': 1000,
        'features': [
            'CSV upload support',
            'Basic templates',
            'File attachments (16MB)',
            'Email support'
        ]
    },
    'basic': {
        'name': 'Basic',
        'price': 2000,
        'daily_limit': 200,
        'features': [
            'Up to 200 emails per day',
            'All Free features',
            'Custom templates',
            'Priority support',
            'Advanced personalization'
        ]
    },
    'professional': {
        'name': 'Professional',
        'price': 3000,
        'daily_limit': 500,
        'features': [
            'Up to 500 emails per day',
            'All Basic features',
            'Email analytics',
            'A/B testing',
            'Custom CSS support',
            'Dedicated support'
        ]
    },
    'enterprise': {
        'name': 'Enterprise',
        'price': 5000,
        'daily_limit': 1000,
        'features': [
            'Up to 1000 emails per day',
            'All Professional features',
            'API access',
            'White-label solution',
            'Custom integrations',
            '24/7 phone support'
        ]
    }
}

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class SignupForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    contact_number = StringField('Contact Number', validators=[DataRequired(), Length(min=8, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create Account')

class BulkMailForm(FlaskForm):
    smtp_provider = SelectField('SMTP Provider', choices=[
        ('zoho', 'Zoho Mail'),
        ('gmail', 'Gmail'),
        ('outlook', 'Outlook/Office365'),
        ('custom', 'Custom SMTP')
    ], default='zoho')
    
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('App Password', validators=[DataRequired()])
    smtp_server = StringField('SMTP Server')
    smtp_port = StringField('SMTP Port')  # Changed from IntegerField to StringField
    subject = StringField('Subject', validators=[DataRequired(), Length(min=1, max=200)])
    body = TextAreaField('Email Body', validators=[DataRequired()])
    email_list = FileField('CSV File', validators=[DataRequired()])
    document = FileField('Attachment (Optional)')
    submit = SubmitField('Send Campaign')
    
    def validate_email_list(self, field):
        """Custom validation for CSV file"""
        if field.data and field.data.filename:
            filename = field.data.filename.lower()
            if not filename.endswith('.csv'):
                raise ValidationError('Only CSV files are allowed.')
    
    def validate_document(self, field):
        """Custom validation for attachment file"""
        if field.data and field.data.filename:
            filename = field.data.filename.lower()
            allowed_extensions = ['.pdf', '.doc', '.docx', '.png', '.jpg', '.jpeg', '.txt']
            if not any(filename.endswith(ext) for ext in allowed_extensions):
                raise ValidationError('Invalid file type. Allowed: PDF, DOC, DOCX, PNG, JPG, JPEG, TXT')
    
    def validate_smtp_server(self, field):
        """Validate SMTP server when custom is selected"""
        if self.smtp_provider.data == 'custom' and not field.data:
            raise ValidationError('SMTP Server is required when using custom SMTP.')
    
    def validate_smtp_port(self, field):
        """Validate SMTP port when custom is selected"""
        if self.smtp_provider.data == 'custom':
            if not field.data:
                raise ValidationError('SMTP Port is required when using custom SMTP.')
            try:
                port = int(field.data)
                if port not in [25, 587, 465, 2525]:
                    raise ValidationError('Invalid SMTP port. Common ports: 25, 587, 465, 2525')
            except ValueError:
                raise ValidationError('SMTP Port must be a valid number.')

# Utility functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_by_id(user_id):
    conn = sqlite3.connect('dazzlego.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def update_email_count(user_id, count):
    conn = sqlite3.connect('dazzlego.db')
    cursor = conn.cursor()
    today = datetime.now().date()
    
    # Check if we need to reset daily count
    cursor.execute('SELECT last_email_date, emails_sent_today FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    
    if result:
        last_date = datetime.strptime(result[0], '%Y-%m-%d').date()
        current_count = result[1]
        
        if last_date < today:
            # Reset count for new day
            new_count = count
        else:
            # Add to existing count
            new_count = current_count + count
        
        cursor.execute('''
            UPDATE users 
            SET emails_sent_today = ?, last_email_date = ? 
            WHERE id = ?
        ''', (new_count, today, user_id))
    
    conn.commit()
    conn.close()

def can_send_emails(user_id, count):
    """Check if user can send specified number of emails"""
    user = get_user_by_id(user_id)
    if not user:
        return False
    
    plan = user[4]  # plan column
    daily_limit = PLANS[plan]['daily_limit']
    emails_sent_today = user[6]  # emails_sent_today column
    
    # Reset count if it's a new day
    last_email_date = datetime.strptime(user[7], '%Y-%m-%d').date()
    today = datetime.now().date()
    
    if last_email_date < today:
        emails_sent_today = 0
    
    return emails_sent_today + count <= daily_limit

def parse_csv_recipients(file_path):
    """Parse CSV file and extract recipients with better error handling"""
    recipients = []
    
    try:
        app_logger.info(f"Parsing CSV file: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            # Detect delimiter
            sample = file.read(1024)
            file.seek(0)
            
            delimiter = ','
            for d in [',', ';', '\t', '|']:
                if sample.count(d) > sample.count(delimiter):
                    delimiter = d
            
            app_logger.info(f"Detected CSV delimiter: '{delimiter}'")
            
            reader = csv.DictReader(file, delimiter=delimiter)
            
            # Normalize field names
            if reader.fieldnames:
                original_fieldnames = reader.fieldnames.copy()
                reader.fieldnames = [col.strip().lower() if col else '' for col in reader.fieldnames]
                app_logger.info(f"CSV columns: {original_fieldnames} -> {reader.fieldnames}")
            
            row_count = 0
            for row in reader:
                row_count += 1
                try:
                    # Clean row data
                    clean_row = {k.strip().lower(): v.strip() if v else '' for k, v in row.items() if k}
                    
                    # Find email with multiple possible column names
                    email = None
                    email_columns = ['email', 'email_address', 'mail', 'e-mail', 'e_mail', 'emailaddress']
                    for col in email_columns:
                        if col in clean_row and clean_row[col]:
                            email = clean_row[col].strip()
                            break
                    
                    if not email:
                        app_logger.warning(f"Row {row_count}: No email found in columns {list(clean_row.keys())}")
                        continue
                    
                    # Validate email
                    if '@' not in email or '.' not in email.split('@')[1]:
                        app_logger.warning(f"Row {row_count}: Invalid email format: {email}")
                        continue
                    
                    # Find name with multiple possible column names
                    name = None
                    name_columns = ['name', 'full_name', 'fullname', 'first_name', 'firstname', 'contact_name', 'person', 'client_name']
                    for col in name_columns:
                        if col in clean_row and clean_row[col]:
                            name = clean_row[col].strip()
                            break
                    
                    if not name:
                        # Generate name from email
                        name = email.split('@')[0].replace('.', ' ').replace('_', ' ').title()
                    
                    # Find company with multiple possible column names
                    company = None
                    company_columns = ['company', 'organization', 'org', 'business', 'company_name', 'firm', 'workplace']
                    for col in company_columns:
                        if col in clean_row and clean_row[col]:
                            company = clean_row[col].strip()
                            break
                    
                    recipient = {
                        'email': email.lower(),
                        'name': name,
                        'company': company or ''
                    }
                    
                    recipients.append(recipient)
                    
                except Exception as row_error:
                    app_logger.error(f"Error processing row {row_count}: {row_error}")
                    continue
            
            app_logger.info(f"Successfully parsed {len(recipients)} recipients from {row_count} rows")
    
    except Exception as e:
        app_logger.error(f"Error parsing CSV: {e}")
        raise Exception(f"Failed to parse CSV file: {e}")
    
    return recipients

# File upload size check
@app.before_request
def before_request():
    """Check file upload size before processing"""
    if request.method == 'POST' and request.endpoint == 'bulk_mail':
        if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
            flash('File too large. Maximum size is 16MB.', 'error')
            return redirect(url_for('bulk_mail'))

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html', plans=PLANS)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    
    if form.validate_on_submit():
        conn = sqlite3.connect('dazzlego.db')
        cursor = conn.cursor()
        
        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (form.email.data,))
        if cursor.fetchone():
            flash('Email already registered. Please use a different email.', 'error')
            conn.close()
            return render_template('signup.html', form=form, plans=PLANS)
        
        # Create new user (always free plan)
        password_hash = generate_password_hash(form.password.data)
        cursor.execute('''
            INSERT INTO users (email, full_name, contact_number, password_hash, plan)
            VALUES (?, ?, ?, ?, ?)
        ''', (form.email.data, form.full_name.data, form.contact_number.data, password_hash, 'free'))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        # Log in the user
        session['user_id'] = user_id
        session['user_name'] = form.full_name.data
        session['user_plan'] = 'free'
        
        flash('Account created successfully! Welcome to DazzloGo.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('signup.html', form=form, plans=PLANS)

@app.route('/signup/payment/<plan>')
@login_required
def signup_payment(plan):
    if plan not in PLANS or plan == 'free':
        return redirect(url_for('dashboard'))
    
    return render_template('signup_payment.html', plan=PLANS[plan])

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        conn = sqlite3.connect('dazzlego.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (form.email.data,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[3], form.password.data):
            session['user_id'] = user[0]
            session['user_name'] = user[2]
            session['user_plan'] = user[4]
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('logout'))
    
    plan_info = PLANS[user[4]]
    
    # Calculate emails sent today
    today = datetime.now().date()
    last_email_date = datetime.strptime(user[7], '%Y-%m-%d').date()
    sent_today = user[6] if last_email_date == today else 0
    
    # Get recent campaigns
    conn = sqlite3.connect('dazzlego.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT recipient_count, subject, sent_at 
        FROM email_campaigns 
        WHERE user_id = ? 
        ORDER BY sent_at DESC 
        LIMIT 5
    ''', (session['user_id'],))
    recent_emails = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', 
                         user=user, 
                         plan_info=plan_info,
                         sent_today=sent_today,
                         daily_limit=plan_info['daily_limit'],
                         can_send=sent_today < plan_info['daily_limit'],
                         recent_emails=recent_emails)

@app.route('/bulk-mail', methods=['GET', 'POST'])
@login_required
def bulk_mail():
    form = BulkMailForm()
    
    if form.validate_on_submit():
        app_logger.info("✅ Form validation passed")
        
        # Check for files
        if not form.email_list.data or not form.email_list.data.filename:
            flash('Please select a CSV file with recipients.', 'error')
            return render_template('bulk_mail.html', form=form)
        
        # Save files with unique names
        timestamp = int(time.time())
        
        try:
            # Save CSV file
            csv_filename = secure_filename(form.email_list.data.filename)
            csv_file = os.path.join(app.config['UPLOAD_FOLDER'], f"csv_{session['user_id']}_{timestamp}_{csv_filename}")
            form.email_list.data.save(csv_file)
            app_logger.info(f"📁 CSV saved: {csv_file}")
            
            # Save attachment if provided
            attachment_file = None
            if form.document.data and form.document.data.filename:
                doc_filename = secure_filename(form.document.data.filename)
                attachment_file = os.path.join(app.config['UPLOAD_FOLDER'], f"doc_{session['user_id']}_{timestamp}_{doc_filename}")
                form.document.data.save(attachment_file)
                app_logger.info(f"📎 Attachment saved: {attachment_file}")
            
            # Parse recipients
            recipients = parse_csv_recipients(csv_file)
            app_logger.info(f"👥 Found {len(recipients)} recipients")
            
            if not recipients:
                flash('No valid email addresses found in CSV file.', 'error')
                return render_template('bulk_mail.html', form=form)
            
            # Check daily limits
            if not can_send_emails(session['user_id'], len(recipients)):
                flash('This campaign exceeds your daily email limit. Please upgrade your plan.', 'error')
                return render_template('bulk_mail.html', form=form)
            
            # Initialize mailer
            smtp_server = form.smtp_server.data if form.smtp_provider.data == 'custom' else None
            smtp_port = form.smtp_port.data if form.smtp_provider.data == 'custom' else None
            
            mailer = AdvancedSMTPMailer(
                email=form.email.data,
                password=form.password.data,
                smtp_server=smtp_server,
                smtp_port=smtp_port
            )
            
            # Send emails
            app_logger.info("🚀 Starting email campaign...")
            results = mailer.send_bulk_emails(
                recipients=recipients,
                subject=form.subject.data,
                body=form.body.data,
                attachment_path=attachment_file
            )
            
            # Update statistics
            update_email_count(session['user_id'], results['successful_sends'])
            
            # Save campaign record
            conn = sqlite3.connect('dazzlego.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO email_campaigns (user_id, subject, recipient_count)
                VALUES (?, ?, ?)
            ''', (session['user_id'], form.subject.data, results['successful_sends']))
            conn.commit()
            conn.close()
            
            if results['successful_sends'] > 0:
                flash(f'Campaign sent successfully to {results["successful_sends"]} recipients!', 'success')
                return redirect(url_for('success', count=results['successful_sends']))
            else:
                flash('Campaign failed. No emails were sent.', 'error')
                
        except Exception as e:
            app_logger.error(f"❌ Campaign error: {e}")
            flash(f'Error processing campaign: {str(e)}', 'error')
        finally:
            # Clean up files
            try:
                if 'csv_file' in locals() and os.path.exists(csv_file):
                    os.remove(csv_file)
                    app_logger.info(f"🗑️ Cleaned up CSV file: {csv_file}")
                if 'attachment_file' in locals() and attachment_file and os.path.exists(attachment_file):
                    os.remove(attachment_file)
                    app_logger.info(f"🗑️ Cleaned up attachment file: {attachment_file}")
            except Exception as cleanup_error:
                app_logger.error(f"Cleanup error: {cleanup_error}")
    
    else:
        # Form validation failed
        if form.errors:
            app_logger.warning("❌ Form validation errors:")
            for field, errors in form.errors.items():
                app_logger.warning(f"  {field}: {errors}")
                for error in errors:
                    flash(f'{field}: {error}', 'error')
    
    return render_template('bulk_mail.html', form=form)

@app.route('/api/validate-email', methods=['POST'])
@login_required
def validate_email():
    """AJAX endpoint for SMTP validation"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        smtp_server = data.get('smtp_server')
        smtp_port = data.get('smtp_port')
        
        if not email or not password:
            return jsonify({'valid': False, 'message': 'Email and password required'})
        
        # Initialize mailer
        mailer = AdvancedSMTPMailer(
            email=email,
            password=password,
            smtp_server=smtp_server,
            smtp_port=int(smtp_port) if smtp_port else None
        )
        
        # Test connection
        result = mailer.test_connection()
        
        if result['success']:
            return jsonify({
                'valid': True, 
                'message': f'Connected to {result["server"]}:{result["port"]} ({result["protocol"]})'
            })
        else:
            return jsonify({
                'valid': False, 
                'message': result['error']
            })
            
    except Exception as e:
        return jsonify({'valid': False, 'message': str(e)})

@app.route('/success')
@login_required
def success():
    count = request.args.get('count', 0, type=int)
    return render_template('success.html', count=count)

@app.route('/upgrade')
@login_required
def upgrade():
    user = get_user_by_id(session['user_id'])
    return render_template('upgrade.html', 
                         plans=PLANS, 
                         current_plan=user[4],
                         user=user)

@app.route('/request-upgrade', methods=['POST'])
@login_required
def request_upgrade():
    """Handle upgrade requests"""
    try:
        data = request.get_json()
        plan_id = data.get('plan_id')
        transaction_id = data.get('transaction_id')
        
        if not plan_id or not transaction_id:
            return jsonify({'success': False, 'message': 'Missing required data'})
        
        if plan_id not in PLANS:
            return jsonify({'success': False, 'message': 'Invalid plan'})
        
        user = get_user_by_id(session['user_id'])
        
        conn = sqlite3.connect('dazzlego.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO upgrade_requests (user_email, requested_plan, transaction_id)
            VALUES (?, ?, ?)
        ''', (user[1], plan_id, transaction_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': 'Upgrade request submitted successfully. Admin will review within 24 hours.'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/upgrades', methods=['GET', 'POST'])
def admin_upgrades():
    """Admin panel for managing upgrade requests"""
    # Simple admin authentication
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'admin' and password == 'dazzlo2025':
            session['admin'] = True
        else:
            flash('Invalid admin credentials', 'error')
            return render_template('admin_login.html')
    
    if not session.get('admin'):
        return render_template('admin_login.html')
    
    # Handle approval
    if request.method == 'POST' and 'approve_id' in request.form:
        approve_id = request.form.get('approve_id')
        
        conn = sqlite3.connect('dazzlego.db')
        cursor = conn.cursor()
        
        # Get upgrade request details
        cursor.execute('''
            SELECT user_email, requested_plan 
            FROM upgrade_requests 
            WHERE id = ? AND status = 'pending'
        ''', (approve_id,))
        
        upgrade_request = cursor.fetchone()
        
        if upgrade_request:
            user_email, requested_plan = upgrade_request
            
            # Update user plan
            cursor.execute('''
                UPDATE users 
                SET plan = ? 
                WHERE email = ?
            ''', (requested_plan, user_email))
            
            # Mark request as approved
            cursor.execute('''
                UPDATE upgrade_requests 
                SET status = 'approved' 
                WHERE id = ?
            ''', (approve_id,))
            
            conn.commit()
            flash(f'Upgrade approved for {user_email} to {requested_plan} plan', 'success')
        
        conn.close()
    
    # Get pending requests
    conn = sqlite3.connect('dazzlego.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, user_email, requested_plan, transaction_id, status, requested_at
        FROM upgrade_requests 
        WHERE status = 'pending'
        ORDER BY requested_at DESC
    ''')
    requests = cursor.fetchall()
    conn.close()
    
    return render_template('admin_upgrades.html', requests=requests, plans=PLANS)

@app.route('/debug/upload-test', methods=['GET', 'POST'])
@login_required
def debug_upload_test():
    """Debug route to test file uploads"""
    if request.method == 'POST':
        files_info = {}
        
        for key, file in request.files.items():
            if file and file.filename:
                files_info[key] = {
                    'filename': file.filename,
                    'content_type': file.content_type,
                    'size': len(file.read())
                }
                file.seek(0)  # Reset file pointer
        
        form_data = {key: value for key, value in request.form.items()}
        
        return jsonify({
            'files': files_info,
            'form_data': form_data,
            'upload_folder': app.config['UPLOAD_FOLDER'],
            'upload_folder_exists': os.path.exists(app.config['UPLOAD_FOLDER'])
        })
    
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Upload Test</title></head>
    <body>
        <h2>File Upload Test</h2>
        <form method="POST" enctype="multipart/form-data">
            <p>CSV File: <input type="file" name="test_csv" accept=".csv"></p>
            <p>Document: <input type="file" name="test_doc"></p>
            <p>Text: <input type="text" name="test_text" placeholder="Test text"></p>
            <p><button type="submit">Test Upload</button></p>
        </form>
        <hr>
        <h3>Instructions:</h3>
        <ul>
            <li>Upload files and check the JSON response</li>
            <li>Verify upload folder exists and is writable</li>
            <li>Check file sizes and types</li>
        </ul>
    </body>
    </html>
    '''

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, 
                         error_message="The page you're looking for doesn't exist"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, 
                         error_message="Internal server error occurred"), 500

@app.errorhandler(413)
def file_too_large(error):
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(url_for('bulk_mail'))

# CLI Commands
@app.cli.command()
def init_database():
    """Initialize the database with tables"""
    init_db()
    print("Database initialized successfully!")

@app.cli.command()
def create_admin():
    """Create admin user for testing"""
    conn = sqlite3.connect('dazzlego.db')
    cursor = conn.cursor()
    
    admin_email = "admin@dazzlo.co.in"
    admin_password = generate_password_hash("admin123")
    
    try:
        cursor.execute('''
            INSERT INTO users (email, full_name, password_hash, plan)
            VALUES (?, ?, ?, ?)
        ''', (admin_email, "Admin User", admin_password, "enterprise"))
        conn.commit()
        print(f"Admin user created: {admin_email} / admin123")
    except sqlite3.IntegrityError:
        print("Admin user already exists")
    
    conn.close()

@app.cli.command()
def create_demo_user():
    """Create demo user for testing"""
    conn = sqlite3.connect('dazzlego.db')
    cursor = conn.cursor()
    
    demo_email = "demo@dazzlo.co.in"
    demo_password = generate_password_hash("demo123")
    
    try:
        cursor.execute('''
            INSERT INTO users (email, full_name, password_hash, plan)
            VALUES (?, ?, ?, ?)
        ''', (demo_email, "Demo User", demo_password, "professional"))
        conn.commit()
        print(f"Demo user created: {demo_email} / demo123")
    except sqlite3.IntegrityError:
        print("Demo user already exists")
    
    conn.close()

@app.cli.command()
def test_upload_permissions():
    """Test upload directory permissions"""
    upload_dir = app.config['UPLOAD_FOLDER']
    test_file = os.path.join(upload_dir, 'test_write.txt')
    
    try:
        # Test directory creation
        os.makedirs(upload_dir, exist_ok=True)
        print(f"✅ Upload directory exists: {upload_dir}")
        
        # Test write permissions
        with open(test_file, 'w') as f:
            f.write('test content')
        print(f"✅ Upload directory is writable")
        
        # Test read permissions
        with open(test_file, 'r') as f:
            content = f.read()
        print(f"✅ Upload directory is readable")
        
        # Clean up
        os.remove(test_file)
        print(f"✅ File operations successful")
        
    except Exception as e:
        print(f"❌ Upload directory error: {e}")
        print(f"📁 Current working directory: {os.getcwd()}")
        print(f"📁 Upload path: {os.path.abspath(upload_dir)}")

if __name__ == '__main__':
    # Initialize database on first run
    init_db()
    
    # Ensure upload directory exists with proper permissions
    upload_dir = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    
    # Test write permissions
    test_file = os.path.join(upload_dir, 'test_write.txt')
    try:
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        print(f"✅ Upload directory is writable: {upload_dir}")
    except Exception as e:
        print(f"❌ Upload directory is not writable: {e}")
        print(f"📁 Please check permissions for: {os.path.abspath(upload_dir)}")
    
    app_logger.info("🚀 Starting DazzloGo Server...")
    print("🚀 Starting DazzloGo Server...")
    print("=" * 60)
    print("🌐 Application URL: http://localhost:5000")
    print("📧 Bulk Email Tool: http://localhost:5000/bulk-mail")
    print("🔧 Debug Upload Test: http://localhost:5000/debug/upload-test")
    print("🛠️ Admin Panel: http://localhost:5000/admin/upgrades")
    print("👤 Admin Login: admin / dazzlo2025")
    print("🎯 Demo User: demo@dazzlo.co.in / demo123")
    print("=" * 60)
    print("📋 Quick Setup:")
    print("1. Visit /bulk-mail")
    print("2. Enter your email credentials")
    print("3. Upload CSV file (email,name,company)")
    print("4. Write your email content")
    print("5. Click 'Test Connection' then 'Send Campaign'")
    print("=" * 60)
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)