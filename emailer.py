#!/usr/bin/env python3
"""
Advanced Universal Bulk Emailer
A comprehensive SMTP bulk mailer with global provider support, intelligent fallbacks,
and enterprise-grade reliability.

Features:
- Universal SMTP support (Zoho, Gmail, Outlook, Yahoo, custom domains)
- Intelligent connection testing and fallbacks
- Advanced email validation and personalization
- Multiple attachment support
- Rate limiting and retry mechanisms
- Comprehensive logging and reporting
- Mobile-optimized HTML templates
- CSV import with flexible column detection
- Real-time progress tracking
"""

import smtplib
import csv
import time
import logging
import socket
import ssl
import json
import os
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email import encoders
from email.utils import formataddr, make_msgid
from html import unescape
import mimetypes
import hashlib


class EmailLogger:
    """Advanced logging system for email operations"""
    
    def __init__(self, log_dir: str = "email_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup loggers
        self.setup_loggers()
        
    def setup_loggers(self):
        """Setup multiple loggers for different purposes"""
        
        # Main logger
        self.logger = logging.getLogger('bulk_emailer')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        log_file = self.log_dir / f"email_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Campaign logger
        self.campaign_logger = logging.getLogger('campaign')
        campaign_file = self.log_dir / f"campaign_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.campaign_log_file = campaign_file
        
    def log_campaign_start(self, recipients_count: int, subject: str):
        """Log campaign start"""
        campaign_data = {
            'start_time': datetime.now().isoformat(),
            'total_recipients': recipients_count,
            'subject': subject,
            'results': []
        }
        
        with open(self.campaign_log_file, 'w', encoding='utf-8') as f:
            json.dump(campaign_data, f, indent=2, ensure_ascii=False)
            
        self.logger.info(f"Campaign started: {recipients_count} recipients")
        
    def log_email_result(self, email: str, status: str, error: str = None):
        """Log individual email result"""
        try:
            with open(self.campaign_log_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            result = {
                'email': email,
                'status': status,
                'timestamp': datetime.now().isoformat(),
                'error': error
            }
            
            data['results'].append(result)
            
            with open(self.campaign_log_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.error(f"Failed to log email result: {e}")


class SMTPConfig:
    """SMTP Configuration manager with comprehensive provider support"""
    
    def __init__(self):
        self.providers = self._load_providers()
        
    def _load_providers(self) -> Dict:
        """Load comprehensive SMTP provider configurations"""
        return {
            # Zoho configurations (global) - Prioritize regional servers
            'zoho.com': [
                ("smtp.zoho.in", 587, False, 'STARTTLS'),    # Try India first for better connectivity
                ("smtp.zoho.com", 587, False, 'STARTTLS'),
                ("smtp.zoho.com", 465, True, 'SSL'),
                ("smtp.zoho.in", 465, True, 'SSL'),
                ("smtppro.zoho.com", 587, False, 'STARTTLS'),
                ("smtppro.zoho.com", 465, True, 'SSL'),
                ("smtp.zoho.com", 25, False, 'PLAIN'),
            ],
            'zoho.in': [
                ("smtp.zoho.in", 587, False, 'STARTTLS'),
                ("smtp.zoho.in", 465, True, 'SSL'),
                ("smtp.zoho.com", 587, False, 'STARTTLS'),
                ("smtp.zoho.com", 465, True, 'SSL'),
            ],
            'zoho.eu': [
                ('smtp.zoho.eu', 587, False, 'STARTTLS'),
                ('smtp.zoho.eu', 465, True, 'SSL'),
                ('smtp.zoho.com', 587, False, 'STARTTLS'),
            ],
            'zoho.com.au': [
                ('smtp.zoho.com.au', 587, False, 'STARTTLS'),
                ('smtp.zoho.com.au', 465, True, 'SSL'),
            ],
            'zoho.jp': [
                ('smtp.zoho.jp', 587, False, 'STARTTLS'),
                ('smtp.zoho.jp', 465, True, 'SSL'),
            ],
            
            # Gmail (Global)
            'gmail.com': [
                ('smtp.gmail.com', 587, False, 'STARTTLS'),
                ('smtp.gmail.com', 465, True, 'SSL'),
                ('smtp.gmail.com', 25, False, 'PLAIN'),
                ('smtp.gmail.com', 2525, False, 'STARTTLS'),
            ],
            'googlemail.com': [
                ('smtp.gmail.com', 587, False, 'STARTTLS'),
                ('smtp.gmail.com', 465, True, 'SSL'),
            ],
            
            # Microsoft/Outlook (Global)
            'outlook.com': [
                ('smtp.office365.com', 587, False, 'STARTTLS'),
                ('smtp-mail.outlook.com', 587, False, 'STARTTLS'),
                ('smtp.live.com', 587, False, 'STARTTLS'),
                ('smtp.office365.com', 25, False, 'PLAIN'),
                ('smtp.office365.com', 2525, False, 'STARTTLS'),
            ],
            'hotmail.com': [
                ('smtp.office365.com', 587, False, 'STARTTLS'),
                ('smtp.live.com', 587, False, 'STARTTLS'),
                ('smtp.hotmail.com', 587, False, 'STARTTLS'),
            ],
            'live.com': [
                ('smtp.office365.com', 587, False, 'STARTTLS'),
                ('smtp.live.com', 587, False, 'STARTTLS'),
            ],
            'office365.com': [
                ('smtp.office365.com', 587, False, 'STARTTLS'),
                ('smtp.office365.com', 25, False, 'PLAIN'),
            ],
            
            # Yahoo (Global)
            'yahoo.com': [
                ('smtp.mail.yahoo.com', 587, False, 'STARTTLS'),
                ('smtp.mail.yahoo.com', 465, True, 'SSL'),
                ('smtp.mail.yahoo.com', 25, False, 'PLAIN'),
            ],
            'yahoo.co.uk': [
                ('smtp.mail.yahoo.co.uk', 587, False, 'STARTTLS'),
                ('smtp.mail.yahoo.co.uk', 465, True, 'SSL'),
            ],
            'yahoo.co.in': [
                ('smtp.mail.yahoo.co.in', 587, False, 'STARTTLS'),
                ('smtp.mail.yahoo.co.in', 465, True, 'SSL'),
            ],
            'ymail.com': [
                ('smtp.mail.yahoo.com', 587, False, 'STARTTLS'),
                ('smtp.mail.yahoo.com', 465, True, 'SSL'),
            ],
            
            # AOL
            'aol.com': [
                ('smtp.aol.com', 587, False, 'STARTTLS'),
                ('smtp.aol.com', 465, True, 'SSL'),
            ],
            
            # iCloud
            'icloud.com': [
                ('smtp.mail.me.com', 587, False, 'STARTTLS'),
                ('smtp.mail.me.com', 465, True, 'SSL'),
            ],
            'me.com': [
                ('smtp.mail.me.com', 587, False, 'STARTTLS'),
                ('smtp.mail.me.com', 465, True, 'SSL'),
            ],
            'mac.com': [
                ('smtp.mail.me.com', 587, False, 'STARTTLS'),
                ('smtp.mail.me.com', 465, True, 'SSL'),
            ],
            
            # Business Providers
            'fastmail.com': [
                ('smtp.fastmail.com', 587, False, 'STARTTLS'),
                ('smtp.fastmail.com', 465, True, 'SSL'),
            ],
            'protonmail.com': [
                ('127.0.0.1', 1025, False, 'BRIDGE'),  # ProtonMail Bridge
                ('smtp.protonmail.com', 587, False, 'STARTTLS'),
            ],
            'tutanota.com': [
                ('smtp.tutanota.com', 587, False, 'STARTTLS'),
                ('smtp.tutanota.com', 465, True, 'SSL'),
            ],
            
            # Regional Providers (India)
            'rediffmail.com': [
                ('smtp.rediffmail.com', 587, False, 'STARTTLS'),
                ('smtp.rediffmail.com', 465, True, 'SSL'),
                ('smtp.rediffmail.com', 25, False, 'PLAIN'),
            ],
            'sify.com': [
                ('smtp.sify.com', 587, False, 'STARTTLS'),
                ('smtp.sify.com', 465, True, 'SSL'),
            ],
            
            # Regional Providers (Europe)
            'gmx.com': [
                ('mail.gmx.com', 587, False, 'STARTTLS'),
                ('mail.gmx.com', 465, True, 'SSL'),
            ],
            'gmx.de': [
                ('mail.gmx.net', 587, False, 'STARTTLS'),
                ('mail.gmx.net', 465, True, 'SSL'),
            ],
            'web.de': [
                ('smtp.web.de', 587, False, 'STARTTLS'),
                ('smtp.web.de', 465, True, 'SSL'),
            ],
            '1und1.de': [
                ('smtp.1und1.de', 587, False, 'STARTTLS'),
                ('smtp.1und1.de', 465, True, 'SSL'),
            ],
            
            # Regional Providers (Asia-Pacific)
            'qq.com': [
                ('smtp.qq.com', 587, False, 'STARTTLS'),
                ('smtp.qq.com', 465, True, 'SSL'),
            ],
            '163.com': [
                ('smtp.163.com', 587, False, 'STARTTLS'),
                ('smtp.163.com', 465, True, 'SSL'),
            ],
            'sina.com': [
                ('smtp.sina.com', 587, False, 'STARTTLS'),
                ('smtp.sina.com', 465, True, 'SSL'),
            ],
            'naver.com': [
                ('smtp.naver.com', 587, False, 'STARTTLS'),
                ('smtp.naver.com', 465, True, 'SSL'),
            ],
            
            # Regional Providers (Others)
            'mail.ru': [
                ('smtp.mail.ru', 587, False, 'STARTTLS'),
                ('smtp.mail.ru', 465, True, 'SSL'),
            ],
            'yandex.com': [
                ('smtp.yandex.com', 587, False, 'STARTTLS'),
                ('smtp.yandex.com', 465, True, 'SSL'),
            ],
            'yandex.ru': [
                ('smtp.yandex.ru', 587, False, 'STARTTLS'),
                ('smtp.yandex.ru', 465, True, 'SSL'),
            ],
        }
    
    def get_configs_for_domain(self, domain: str) -> List[Tuple]:
        """Get SMTP configurations for a specific domain"""
        domain = domain.lower()
        
        # Direct match
        if domain in self.providers:
            configs = self.providers[domain].copy()
        else:
            configs = []
        
        # Generate generic configurations for custom domains
        generic_configs = [
            (f'smtp.{domain}', 587, False, 'STARTTLS'),
            (f'smtp.{domain}', 465, True, 'SSL'),
            (f'mail.{domain}', 587, False, 'STARTTLS'),
            (f'mail.{domain}', 465, True, 'SSL'),
            (f'email.{domain}', 587, False, 'STARTTLS'),
            (f'email.{domain}', 465, True, 'SSL'),
            (f'mx.{domain}', 587, False, 'STARTTLS'),
            (f'mx.{domain}', 465, True, 'SSL'),
            (f'outgoing.{domain}', 587, False, 'STARTTLS'),
            (f'send.{domain}', 587, False, 'STARTTLS'),
            (f'smtp.{domain}', 25, False, 'PLAIN'),
            (f'smtp.{domain}', 2525, False, 'STARTTLS'),
            (f'mail.{domain}', 25, False, 'PLAIN'),
            (f'mail.{domain}', 2525, False, 'STARTTLS'),
        ]
        
        configs.extend(generic_configs)
        
        # Add fallback configurations (major providers)
        fallback_configs = [
            ('smtp.zoho.com', 587, False, 'STARTTLS'),
            ('smtp.zoho.in', 587, False, 'STARTTLS'),
            ('smtp.gmail.com', 587, False, 'STARTTLS'),
            ('smtp.office365.com', 587, False, 'STARTTLS'),
        ]
        
        configs.extend(fallback_configs)
        
        return configs


class EmailValidator:
    """Advanced email validation and recipient management"""
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email address using comprehensive regex"""
        pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize email address"""
        return email.strip().lower()
    
    @staticmethod
    def extract_name_from_email(email: str) -> str:
        """Extract a reasonable name from email address"""
        local_part = email.split('@')[0]
        
        # Remove numbers and special characters
        name = re.sub(r'[0-9._-]', ' ', local_part)
        name = ' '.join(word.capitalize() for word in name.split() if word)
        
        return name if name else "Valued Customer"


class CSVManager:
    """Advanced CSV handling with flexible column detection"""
    
    def __init__(self, logger: EmailLogger):
        self.logger = logger
        
    def detect_delimiter(self, file_path: str) -> str:
        """Auto-detect CSV delimiter"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            sample = file.read(2048)
            
        delimiters = [',', ';', '\t', '|', ':']
        delimiter_scores = {}
        
        for delimiter in delimiters:
            lines = sample.split('\n')[:5]  # Check first 5 lines
            scores = [line.count(delimiter) for line in lines if line.strip()]
            
            if scores:
                # Good delimiter should have consistent counts across lines
                avg_score = sum(scores) / len(scores)
                consistency = 1 - (max(scores) - min(scores)) / (max(scores) + 1)
                delimiter_scores[delimiter] = avg_score * consistency
        
        return max(delimiter_scores, key=delimiter_scores.get) if delimiter_scores else ','
    
    def read_recipients(self, csv_path: str) -> List[Dict[str, str]]:
        """Read recipients from CSV with intelligent column detection"""
        recipients = []
        
        try:
            delimiter = self.detect_delimiter(csv_path)
            self.logger.logger.info(f"Detected CSV delimiter: '{delimiter}'")
            
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as file:
                reader = csv.DictReader(file, delimiter=delimiter)
                
                # Normalize column names
                if reader.fieldnames:
                    reader.fieldnames = [self._normalize_column_name(col) for col in reader.fieldnames]
                
                for row_num, row in enumerate(reader, 2):  # Start from 2 (header is row 1)
                    try:
                        recipient = self._extract_recipient_from_row(row, row_num)
                        if recipient:
                            recipients.append(recipient)
                    except Exception as e:
                        self.logger.logger.warning(f"Error processing row {row_num}: {e}")
                        
        except Exception as e:
            self.logger.logger.error(f"Error reading CSV file: {e}")
            raise Exception(f"Failed to read CSV file: {e}")
        
        if not recipients:
            raise Exception("No valid email addresses found in CSV file")
        
        self.logger.logger.info(f"Successfully loaded {len(recipients)} recipients")
        return recipients
    
    def _normalize_column_name(self, col_name: str) -> str:
        """Normalize column name for better matching"""
        if not col_name:
            return ''
        return col_name.strip().lower().replace(' ', '_').replace('-', '_')
    
    def _extract_recipient_from_row(self, row: Dict, row_num: int) -> Optional[Dict[str, str]]:
        """Extract recipient information from CSV row"""
        
        # Email column patterns
        email_patterns = ['email', 'email_address', 'mail', 'e_mail', 'emailaddress', 'e_mail_address']
        email = self._find_value_by_patterns(row, email_patterns)
        
        if not email or not EmailValidator.is_valid_email(email):
            self.logger.logger.warning(f"Invalid email in row {row_num}: {email}")
            return None
        
        email = EmailValidator.normalize_email(email)
        
        # Name column patterns
        name_patterns = ['name', 'full_name', 'fullname', 'first_name', 'firstname', 'contact_name', 'person']
        name = self._find_value_by_patterns(row, name_patterns)
        
        # Company column patterns
        company_patterns = ['company', 'organization', 'org', 'business', 'company_name', 'firm']
        company = self._find_value_by_patterns(row, company_patterns)
        
        # Title column patterns
        title_patterns = ['title', 'position', 'job_title', 'designation', 'role']
        title = self._find_value_by_patterns(row, title_patterns)
        
        # Generate display name
        if name:
            display_name = name.strip()
        elif company:
            display_name = f"Team {company}"
        else:
            display_name = EmailValidator.extract_name_from_email(email)
        
        return {
            'email': email,
            'name': display_name,
            'raw_name': name or '',
            'company': company or '',
            'title': title or '',
            'display_name': display_name
        }
    
    def _find_value_by_patterns(self, row: Dict, patterns: List[str]) -> str:
        """Find value in row using multiple column name patterns"""
        for pattern in patterns:
            for key, value in row.items():
                if key and pattern in key:
                    return str(value).strip() if value else ''
        return ''


class AdvancedBulkEmailer:
    """Advanced Universal Bulk Emailer with enterprise features"""
    
    def __init__(self, email: str, password: str, smtp_server: str = None, smtp_port: int = None):
        self.email = email.strip()
        self.password = password
        self.domain = email.split('@')[-1].lower()
        
        # Initialize components
        self.logger = EmailLogger()
        self.smtp_config = SMTPConfig()
        self.csv_manager = CSVManager(self.logger)
        
        # Working SMTP configuration
        self.working_config = None
        
        # Custom SMTP if provided
        self.custom_smtp = (smtp_server, smtp_port) if smtp_server and smtp_port else None
        
        # Statistics
        self.stats = {
            'total_emails': 0,
            'successful_sends': 0,
            'failed_sends': 0,
            'start_time': None,
            'end_time': None
        }
        
        self.logger.logger.info(f"Initialized Advanced Bulk Emailer for {email}")
    
    def test_smtp_connection(self) -> bool:
        """Test SMTP connection with comprehensive fallback"""
        
        configs = self.smtp_config.get_configs_for_domain(self.domain)
        
        # Add custom SMTP at the beginning if provided
        if self.custom_smtp:
            server, port = self.custom_smtp
            custom_configs = [
                (server, port, False, 'STARTTLS'),
                (server, port, True, 'SSL'),
                (server, port, False, 'PLAIN'),
            ]
            configs = custom_configs + configs
        
        print(f"🔍 Testing {len(configs)} SMTP configurations for {self.domain}...")
        
        for i, (server, port, use_ssl, protocol) in enumerate(configs, 1):
            try:
                print(f"🔄 [{i}/{len(configs)}] Testing {server}:{port} ({protocol})...")
                
                if self._test_single_smtp_config(server, port, use_ssl):
                    self.working_config = (server, port, use_ssl, protocol)
                    print(f"✅ SUCCESS! Connected to {server}:{port} ({protocol})")
                    self.logger.logger.info(f"SMTP connection established: {server}:{port} ({protocol})")
                    return True
                    
            except Exception as e:
                print(f"❌ Failed {server}:{port} - {str(e)[:100]}")
                continue
        
        self._show_troubleshooting_guide()
        return False
    
    def _test_single_smtp_config(self, server: str, port: int, use_ssl: bool) -> bool:
        """Test a single SMTP configuration"""
        
        try:
            if use_ssl:
                # SSL connection (port 465)
                context = ssl.create_default_context()
                smtp_server = smtplib.SMTP_SSL(server, port, timeout=15, context=context)
            else:
                # STARTTLS connection (port 587, 25, etc.)
                smtp_server = smtplib.SMTP(server, port, timeout=15)
                smtp_server.ehlo()
                
                if smtp_server.has_extn('STARTTLS'):
                    smtp_server.starttls()
                    smtp_server.ehlo()
            
            # Test authentication
            smtp_server.login(self.email, self.password)
            smtp_server.quit()
            return True
            
        except socket.timeout:
            raise Exception("Connection timeout")
        except socket.gaierror:
            raise Exception("DNS resolution failed")
        except smtplib.SMTPAuthenticationError:
            raise Exception("Authentication failed")
        except smtplib.SMTPConnectError:
            raise Exception("Connection refused")
        except Exception as e:
            raise Exception(f"Unknown error: {e}")
    
    def _show_troubleshooting_guide(self):
        """Display comprehensive troubleshooting guide"""
        
        print("\n" + "="*80)
        print("❌ SMTP CONNECTION FAILED - TROUBLESHOOTING GUIDE")
        print("="*80)
        
        if 'zoho' in self.domain:
            print("📧 ZOHO EMAIL TROUBLESHOOTING:")
            print("1. 🔑 Generate App-Specific Password:")
            print("   • Go to: https://accounts.zoho.com/home#security/apppasswords")
            print("   • Create password for 'Email Clients'")
            print("   • Use this password instead of your regular password")
            print("2. ✅ Enable IMAP: Zoho Mail → Settings → IMAP Access → Enable")
            print("3. 🔒 Enable 2FA (required for app passwords)")
            print("4. 🌐 Regional servers:")
            print("   • smtp.zoho.com (Global)")
            print("   • smtp.zoho.in (India)")
            print("   • smtp.zoho.eu (Europe)")
            
        elif 'gmail' in self.domain:
            print("📧 GMAIL TROUBLESHOOTING:")
            print("1. 🔒 Enable 2FA: https://myaccount.google.com/security")
            print("2. 🔑 Generate App Password:")
            print("   • Google Account → Security → App passwords")
            print("   • Select 'Mail' and generate password")
            print("3. ❌ Don't use regular Gmail password")
            
        elif any(x in self.domain for x in ['outlook', 'hotmail', 'live']):
            print("📧 MICROSOFT EMAIL TROUBLESHOOTING:")
            print("1. 🔒 Enable 2FA: https://account.microsoft.com/security")
            print("2. 🔑 Generate App Password:")
            print("   • Security → Advanced security options → App passwords")
            print("3. 📧 Use smtp.office365.com:587")
        
        print("\n🔧 GENERAL TROUBLESHOOTING:")
        print("1. ✅ Double-check email and password")
        print("2. 🌐 Test internet connection")
        print("3. 🔥 Check firewall/antivirus settings")
        print("4. 🏢 Corporate network? Check proxy settings")
        print("5. 📱 Try different network (mobile hotspot)")
        print("6. ⏰ Wait and retry (rate limiting)")
        
        print(f"\n🆘 NEED HELP? Contact support:")
        print("📞 Phone: +91 9373015503")
        print("📧 Email: info@dazzlo.co.in")
        print("="*80)
    
    def _create_smtp_connection(self):
        """Create SMTP connection using working configuration"""
        
        if not self.working_config:
            if not self.test_smtp_connection():
                raise Exception("No working SMTP configuration found")
        
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
    
    def load_recipients_from_csv(self, csv_path: str) -> List[Dict[str, str]]:
        """Load recipients from CSV file"""
        return self.csv_manager.read_recipients(csv_path)
    
    def create_email_message(self, recipient: Dict[str, str], subject: str, 
                           body: str, attachments: List[str] = None) -> MIMEMultipart:
        """Create personalized email message with attachments"""
        
        # Create message
        msg = MIMEMultipart('mixed')
        
        # Headers
        sender_name = self.email.split('@')[0].replace('.', ' ').replace('_', ' ').title()
        msg['From'] = formataddr((sender_name, self.email))
        msg['To'] = formataddr((recipient['display_name'], recipient['email']))
        msg['Subject'] = self._personalize_text(subject, recipient)
        msg['Message-ID'] = make_msgid()
        
        # Create body container
        body_container = MIMEMultipart('alternative')
        
        # Personalize body
        personalized_body = self._personalize_text(body, recipient)
        
        # Add text and HTML versions
        if self._is_html_content(personalized_body):
            # HTML version
            html_part = MIMEText(personalized_body, 'html', 'utf-8')
            body_container.attach(html_part)
            
            # Plain text version
            plain_text = self._html_to_text(personalized_body)
            text_part = MIMEText(plain_text, 'plain', 'utf-8')
            body_container.attach(text_part)
        else:
            # Plain text only
            text_part = MIMEText(personalized_body, 'plain', 'utf-8')
            body_container.attach(text_part)
        
        msg.attach(body_container)
        
        # Add attachments
        if attachments:
            for attachment_path in attachments:
                if os.path.exists(attachment_path):
                    self._add_attachment(msg, attachment_path)
                else:
                    self.logger.logger.warning(f"Attachment not found: {attachment_path}")
        
        return msg
    
    def _personalize_text(self, text: str, recipient: Dict[str, str]) -> str:
        """Personalize text with recipient data"""
        
        personalized = text
        
        # Standard replacements
        replacements = {
            '{name}': recipient.get('display_name', ''),
            '{first_name}': recipient.get('raw_name', '').split()[0] if recipient.get('raw_name') else '',
            '{email}': recipient.get('email', ''),
            '{company}': recipient.get('company', ''),
            '{title}': recipient.get('title', ''),
            '{Company}': recipient.get('company', ''),  # Capitalized version
        }
        
        for placeholder, value in replacements.items():
            personalized = personalized.replace(placeholder, value)
        
        # Handle conditional text
        personalized = self._handle_conditional_text(personalized, recipient)
        
        return personalized
    
    def _handle_conditional_text(self, text: str, recipient: Dict[str, str]) -> str:
        """Handle conditional text based on available data"""
        
        # Pattern: {if:company}Hello {company} team{/if:company}
        pattern = r'\{if:(\w+)\}(.*?)\{/if:\1\}'
        
        def replace_conditional(match):
            field = match.group(1)
            content = match.group(2)
            
            if recipient.get(field) and recipient[field].strip():
                return self._personalize_text(content, recipient)
            return ''
        
        return re.sub(pattern, replace_conditional, text, flags=re.DOTALL)
    
    def _is_html_content(self, content: str) -> bool:
        """Check if content contains HTML"""
        html_tags = ['<html>', '<body>', '<p>', '<div>', '<span>', '<br>', '<strong>', '<em>']
        content_lower = content.lower()
        return any(tag in content_lower for tag in html_tags)
    
    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML to plain text"""
        
        # Simple HTML to text conversion
        text = html_content
        
        # Replace common HTML elements
        replacements = [
            (r'<br\s*/?>', '\n'),
            (r'</p>', '\n\n'),
            (r'<p[^>]*>', ''),
            (r'<h[1-6][^>]*>', '\n\n'),
            (r'</h[1-6]>', '\n'),
            (r'<li[^>]*>', '• '),
            (r'</li>', '\n'),
            (r'<ul[^>]*>|</ul>', '\n'),
            (r'<ol[^>]*>|</ol>', '\n'),
            (r'<strong[^>]*>|</strong>|<b[^>]*>|</b>', '**'),
            (r'<em[^>]*>|</em>|<i[^>]*>|</i>', '*'),
            (r'<div[^>]*>', '\n'),
            (r'</div>', ''),
            (r'<span[^>]*>|</span>', ''),
            (r'<a[^>]*>', ''),
            (r'</a>', ''),
        ]
        
        for pattern, replacement in replacements:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        
        # Remove remaining HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Decode HTML entities
        text = unescape(text)
        
        # Clean up whitespace
        text = re.sub(r'\n\s*\n\s*\n', '\n\n', text)
        text = text.strip()
        
        return text
    
    def _add_attachment(self, msg: MIMEMultipart, file_path: str):
        """Add attachment to email message"""
        
        try:
            # Guess the content type based on the file's extension
            ctype, encoding = mimetypes.guess_type(file_path)
            if ctype is None or encoding is not None:
                ctype = 'application/octet-stream'
            
            maintype, subtype = ctype.split('/', 1)
            
            with open(file_path, 'rb') as fp:
                if maintype == 'text':
                    attachment = MIMEText(fp.read().decode('utf-8'), _subtype=subtype)
                elif maintype == 'image':
                    attachment = MIMEImage(fp.read(), _subtype=subtype)
                else:
                    attachment = MIMEBase(maintype, subtype)
                    attachment.set_payload(fp.read())
                    encoders.encode_base64(attachment)
            
            # Set filename
            filename = os.path.basename(file_path)
            attachment.add_header(
                'Content-Disposition',
                f'attachment; filename="{filename}"'
            )
            
            msg.attach(attachment)
            self.logger.logger.info(f"Added attachment: {filename}")
            
        except Exception as e:
            self.logger.logger.error(f"Failed to attach {file_path}: {e}")
    
    def send_bulk_emails(self, recipients: List[Dict[str, str]], subject: str, 
                        body: str, attachments: List[str] = None, 
                        delay: float = 1.0, max_retries: int = 3) -> Dict:
        """Send bulk emails with advanced error handling and retries"""
        
        # Initialize statistics
        self.stats = {
            'total_emails': len(recipients),
            'successful_sends': 0,
            'failed_sends': 0,
            'start_time': datetime.now(),
            'end_time': None,
            'failed_recipients': []
        }
        
        # Test connection first
        if not self.working_config:
            print("🔄 Testing SMTP connection...")
            if not self.test_smtp_connection():
                raise Exception("Could not establish SMTP connection")
        
        # Log campaign start
        self.logger.log_campaign_start(len(recipients), subject)
        
        print(f"📧 Starting bulk email campaign...")
        print(f"📊 Recipients: {len(recipients)}")
        print(f"📋 Subject: {subject}")
        print(f"🔗 SMTP: {self.working_config[0]}:{self.working_config[1]}")
        print(f"⏱️  Delay: {delay}s between emails")
        print("-" * 60)
        
        smtp_server = None
        reconnect_counter = 0
        max_reconnects = 10
        
        try:
            smtp_server = self._create_smtp_connection()
            
            for i, recipient in enumerate(recipients, 1):
                email_sent = False
                last_error = None
                
                # Retry mechanism
                for attempt in range(max_retries):
                    try:
                        # Reconnect if needed
                        if reconnect_counter >= max_reconnects:
                            print("🔄 Reconnecting to SMTP server...")
                            smtp_server.quit()
                            smtp_server = self._create_smtp_connection()
                            reconnect_counter = 0
                        
                        # Create and send message
                        msg = self.create_email_message(recipient, subject, body, attachments)
                        smtp_server.send_message(msg)
                        
                        # Success
                        self.stats['successful_sends'] += 1
                        self.logger.log_email_result(recipient['email'], 'success')
                        
                        print(f"✅ [{i}/{len(recipients)}] Sent to {recipient['display_name']} <{recipient['email']}>")
                        
                        email_sent = True
                        reconnect_counter += 1
                        break
                        
                    except smtplib.SMTPServerDisconnected:
                        # Server disconnected, try to reconnect
                        try:
                            smtp_server = self._create_smtp_connection()
                            reconnect_counter = 0
                            continue
                        except Exception as e:
                            last_error = f"Reconnection failed: {e}"
                            break
                            
                    except smtplib.SMTPRecipientsRefused as e:
                        last_error = f"Recipient refused: {e}"
                        break  # Don't retry for this type of error
                        
                    except smtplib.SMTPDataError as e:
                        last_error = f"Data error: {e}"
                        if attempt < max_retries - 1:
                            time.sleep(2 ** attempt)  # Exponential backoff
                        continue
                        
                    except Exception as e:
                        last_error = str(e)
                        if attempt < max_retries - 1:
                            time.sleep(1)
                        continue
                
                # Handle failed email
                if not email_sent:
                    self.stats['failed_sends'] += 1
                    self.stats['failed_recipients'].append({
                        'email': recipient['email'],
                        'name': recipient['display_name'],
                        'error': last_error
                    })
                    self.logger.log_email_result(recipient['email'], 'failed', last_error)
                    
                    print(f"❌ [{i}/{len(recipients)}] Failed to send to {recipient['email']}: {last_error}")
                
                # Progress indicator
                if i % 10 == 0:
                    success_rate = (self.stats['successful_sends'] / i) * 100
                    print(f"📊 Progress: {i}/{len(recipients)} ({success_rate:.1f}% success rate)")
                
                # Rate limiting
                if delay > 0 and i < len(recipients):
                    time.sleep(delay)
        
        except KeyboardInterrupt:
            print("\n⚠️  Campaign interrupted by user")
        except Exception as e:
            print(f"\n❌ Campaign failed: {e}")
            self.logger.logger.error(f"Campaign failed: {e}")
        finally:
            if smtp_server:
                try:
                    smtp_server.quit()
                except:
                    pass
            
            self.stats['end_time'] = datetime.now()
            self._print_campaign_summary()
        
        return self.stats
    
    def _print_campaign_summary(self):
        """Print comprehensive campaign summary"""
        
        duration = self.stats['end_time'] - self.stats['start_time']
        success_rate = (self.stats['successful_sends'] / self.stats['total_emails']) * 100
        
        print("\n" + "="*60)
        print("📊 CAMPAIGN SUMMARY")
        print("="*60)
        print(f"📧 Total Emails: {self.stats['total_emails']}")
        print(f"✅ Successful: {self.stats['successful_sends']}")
        print(f"❌ Failed: {self.stats['failed_sends']}")
        print(f"📈 Success Rate: {success_rate:.1f}%")
        print(f"⏱️  Duration: {duration}")
        print(f"📄 Log File: {self.logger.campaign_log_file}")
        
        if self.stats['failed_recipients']:
            print(f"\n❌ Failed Recipients:")
            for failed in self.stats['failed_recipients'][:10]:  # Show first 10
                print(f"   • {failed['email']} - {failed['error'][:50]}...")
            
            if len(self.stats['failed_recipients']) > 10:
                print(f"   ... and {len(self.stats['failed_recipients']) - 10} more")
        
        print("="*60)
    
    def create_sample_csv(self, filename: str = "sample_recipients.csv"):
        """Create a sample CSV file for testing"""
        
        sample_data = [
            ["email", "name", "company", "title"],
            ["john.doe@example.com", "John Doe", "Tech Corp", "CEO"],
            ["jane.smith@business.com", "Jane Smith", "Business Solutions", "Manager"],
            ["mike.johnson@startup.io", "Mike Johnson", "Innovation Ltd", "Developer"],
            ["sarah.wilson@company.org", "Sarah Wilson", "Global Systems", "Director"],
            ["alex.brown@enterprise.net", "Alex Brown", "Enterprise Inc", "Analyst"]
        ]
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerows(sample_data)
            
            print(f"✅ Created sample CSV file: {filename}")
            print("📝 Update this file with your recipient list before sending emails")
            return True
            
        except Exception as e:
            print(f"❌ Error creating sample CSV: {e}")
            return False


def main():
    """Main function with interactive CLI"""
    
    print("="*80)
    print("🚀 ADVANCED UNIVERSAL BULK EMAILER")
    print("="*80)
    print("✨ Features: Global SMTP Support | Smart Fallbacks | HTML Templates")
    print("🌍 Supports: Zoho, Gmail, Outlook, Yahoo, Custom Domains")
    print("="*80)
    
    # Configuration - Update with your actual credentials
    EMAIL = "siddhant@dazzlo.co.in"
    PASSWORD = "your-app-specific-password-here"  # IMPORTANT: Use App-Specific Password, NOT regular password!
    CSV_FILE = "email_list.csv"
    
    # Email content - Professional recruitment template
    SUBJECT = "🎯 Transform Your Hiring Strategy with DazzloHR Solutions"
    
    BODY = """
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background: #f8f9fa; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }
            .header h1 { margin: 0; font-size: 28px; font-weight: 700; }
            .content { padding: 30px; }
            .greeting { font-size: 18px; margin-bottom: 25px; }
            .highlight { color: #667eea; font-weight: 600; }
            .services { background: #f8f9ff; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #667eea; }
            .services h3 { color: #2d3748; margin-bottom: 15px; font-size: 20px; }
            .service-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 20px; }
            .service-item { background: white; padding: 15px; border-radius: 6px; border: 1px solid #e2e8f0; font-size: 14px; }
            .cta { background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%); color: white; padding: 30px; border-radius: 8px; text-align: center; margin: 30px 0; }
            .cta h3 { margin-bottom: 15px; font-size: 22px; }
            .signature { background: #f7fafc; padding: 25px; border-radius: 8px; text-align: center; border: 1px solid #e2e8f0; }
            .signature .name { font-size: 20px; font-weight: 700; color: #2d3748; }
            .signature .title { color: #718096; margin: 5px 0; }
            .signature .company { font-size: 18px; font-weight: 600; color: #667eea; margin: 10px 0; }
            .contact { display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; margin-top: 15px; }
            .contact span { color: #4a5568; font-size: 14px; font-weight: 500; }
            @media (max-width: 600px) {
                body { padding: 10px; }
                .container { border-radius: 0; }
                .header, .content, .cta, .signature { padding: 20px 15px; }
                .service-list { grid-template-columns: 1fr; }
                .contact { flex-direction: column; gap: 10px; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎯 DazzloHR Solutions</h1>
                <p>Your Strategic Recruitment Partner</p>
            </div>
            
            <div class="content">
                <div class="greeting">
                    Dear <strong>{if:company}{company} Team{/if:company}{if:name}{name}{/if:name}</strong>,<br><br>
                    
                    Hope this email finds you well! I'm reaching out to explore how <span class="highlight">DazzloHR Solutions</span> can transform your hiring strategy and help you secure top talent faster than ever.
                    
                    {if:company}<br><br>We understand that {company} requires exceptional talent to drive growth and innovation.{/if:company}
                </div>
                
                <div class="services">
                    <h3>🚀 Our Comprehensive Services</h3>
                    <p>We specialize in end-to-end recruitment solutions across all industries and experience levels:</p>
                    
                    <div class="service-list">
                        <div class="service-item">✨ <strong>Executive Search</strong><br>C-Suite & Leadership roles</div>
                        <div class="service-item">💼 <strong>Mid-Level Hiring</strong><br>Managers & Senior professionals</div>
                        <div class="service-item">🚀 <strong>Bulk Recruitment</strong><br>Large-scale hiring across India</div>
                        <div class="service-item">💻 <strong>Tech Recruitment</strong><br>IT, Software & Digital roles</div>
                        <div class="service-item">⏰ <strong>Contract Staffing</strong><br>Project-based & temporary roles</div>
                        <div class="service-item">🎓 <strong>Campus Hiring</strong><br>Fresh graduates & entry-level</div>
                        <div class="service-item">🌐 <strong>Remote Hiring</strong><br>Global talent acquisition</div>
                        <div class="service-item">🔧 <strong>Niche Specialists</strong><br>Industry-specific experts</div>
                    </div>
                </div>
                
                <div class="cta">
                    <h3>🤝 Ready to Transform Your Hiring?</h3>
                    <p>We combine <strong>speed, precision, and cultural alignment</strong> to deliver candidates who don't just meet your requirements—they exceed them.</p>
                    <p>Let's schedule a brief call to discuss how we can streamline {if:company}{company}'s{/if:company} recruitment process and help you build a world-class team.</p>
                </div>
                
                <div class="signature">
                    <div class="name">Siddhant Suryavanshi</div>
                    <div class="title">Founder & Managing Director</div>
                    <div class="company">DazzloHR Solutions</div>
                    
                    <div class="contact">
                        <span>📱 +91-9373015503</span>
                        <span>✉️ siddhant@dazzlo.co.in</span>
                        <span>🌐 www.dazzlo.co.in</span>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Attachments
    ATTACHMENTS = ["DazzloHR_Company_Profile.pdf"]  # Add your PDF files here
    
    try:
        # Initialize mailer with working SMTP configuration
        print(f"🔧 Initializing mailer for: {EMAIL}")
        # Force working SMTP server for dazzlo.co.in domain
        mailer = AdvancedBulkEmailer(EMAIL, PASSWORD, "smtp.zoho.in", 587)
        
        # Check if CSV exists, create sample if not
        if not os.path.exists(CSV_FILE):
            print(f"📄 CSV file '{CSV_FILE}' not found.")
            if mailer.create_sample_csv(CSV_FILE):
                print("👆 Please update the CSV file with your recipients and run again.")
                return
        
        # Load recipients
        print(f"📖 Loading recipients from {CSV_FILE}...")
        recipients = mailer.load_recipients_from_csv(CSV_FILE)
        
        if not recipients:
            print("❌ No valid recipients found!")
            return
        
        print(f"✅ Loaded {len(recipients)} recipients")
        
        # Show sample recipients
        print("\n📋 Sample recipients:")
        for i, recipient in enumerate(recipients[:3], 1):
            print(f"  {i}. {recipient['display_name']} <{recipient['email']}> ({recipient['company']})")
        if len(recipients) > 3:
            print(f"  ... and {len(recipients) - 3} more")
        
        # Check attachments
        valid_attachments = []
        for attachment in ATTACHMENTS:
            if os.path.exists(attachment):
                valid_attachments.append(attachment)
                print(f"✅ Found attachment: {attachment}")
            else:
                print(f"⚠️  Attachment not found: {attachment}")
        
        # Confirm sending
        print(f"\n📧 Email Subject: {SUBJECT}")
        print(f"📎 Attachments: {len(valid_attachments)}")
        
        confirm = input(f"\n🚀 Send {len(recipients)} emails? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ Campaign cancelled.")
            return
        
        # Send emails
        print("\n🚀 Starting email campaign...")
        results = mailer.send_bulk_emails(
            recipients=recipients,
            subject=SUBJECT,
            body=BODY,
            attachments=valid_attachments if valid_attachments else None,
            delay=2.0,  # 2 seconds between emails
            max_retries=3
        )
        
        # Final summary
        if results['successful_sends'] > 0:
            print(f"\n🎉 Campaign completed successfully!")
            print(f"📊 {results['successful_sends']}/{results['total_emails']} emails sent")
        else:
            print(f"\n❌ Campaign failed - no emails were sent")
            
    except KeyboardInterrupt:
        print("\n⚠️  Program interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("🆘 Need help? Contact: +91 9373015503")


if __name__ == "__main__":
    main()