import smtplib
import csv
import time
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formataddr
import os
import re
from typing import List, Dict, Optional
from html import unescape
import io

class BulkMailer:
    """Generic bulk email sender supporting Zoho, Outlook, Gmail, and Google Workspace SMTP"""
    SMTP_CONFIGS = [
        # Gmail and Google Workspace
        {
            'domains': ['gmail.com', 'googlemail.com'],
            'server': 'smtp.gmail.com',
            'port': 587
        },
        {
            'domains': ['outlook.com', 'hotmail.com', 'live.com', 'office365.com', 'microsoft.com'],
            'server': 'smtp.office365.com',
            'port': 587
        },
        # Zoho
        {
            'domains': ['zoho.com', 'zohomail.com'],
            'server': 'smtp.zoho.com',
            'port': 587
        },
        {
            'domains': ['zoho.in'],
            'server': 'smtp.zoho.in',
            'port': 587
        },
        {
            'domains': ['zoho.eu'],
            'server': 'smtp.zoho.eu',
            'port': 587
        },
    ]

    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password
        self.smtp_server, self.smtp_port = self._detect_smtp_server(email)
        self.logger = logging.getLogger(__name__)
        print(f"DEBUG: Using SMTP server: {self.smtp_server} for email: {email}")

    def _detect_smtp_server(self, email: str):
        domain = email.split('@')[-1].lower()
        for config in self.SMTP_CONFIGS:
            if any(domain.endswith(d) for d in config['domains']):
                return config['server'], config['port']
        # Default fallback
        return 'smtp.gmail.com', 587

    def test_connection(self) -> bool:
        """Test SMTP connection with provided credentials"""
        try:
            print(f"DEBUG: Testing connection to {self.smtp_server}:{self.smtp_port}")
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email, self.password)
            server.quit()
            print("DEBUG: Connection successful!")
            return True
        except Exception as e:
            print(f"DEBUG: Connection failed: {e}")
            raise Exception(f"Failed to connect to SMTP: {str(e)}")
    
    def validate_email(self, email: str) -> bool:
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def html_to_plain_text(self, html_content: str) -> str:
        """Convert HTML content to plain text for email compatibility"""
        # Remove HTML tags but preserve structure
        plain_text = html_content
        
        # Convert common HTML elements to plain text equivalents
        plain_text = re.sub(r'<br\s*/?>', '\n', plain_text)
        plain_text = re.sub(r'</p>', '\n\n', plain_text)
        plain_text = re.sub(r'<p[^>]*>', '', plain_text)
        plain_text = re.sub(r'<h[1-6][^>]*>', '\n\n', plain_text)
        plain_text = re.sub(r'</h[1-6]>', '\n', plain_text)
        plain_text = re.sub(r'<li[^>]*>', '• ', plain_text)
        plain_text = re.sub(r'</li>', '\n', plain_text)
        plain_text = re.sub(r'<ul[^>]*>|</ul>', '\n', plain_text)
        plain_text = re.sub(r'<ol[^>]*>|</ol>', '\n', plain_text)
        plain_text = re.sub(r'<strong[^>]*>|</strong>', '**', plain_text)
        plain_text = re.sub(r'<b[^>]*>|</b>', '**', plain_text)
        plain_text = re.sub(r'<em[^>]*>|</em>', '*', plain_text)
        plain_text = re.sub(r'<i[^>]*>|</i>', '*', plain_text)
        plain_text = re.sub(r'<div[^>]*>', '\n', plain_text)
        plain_text = re.sub(r'</div>', '', plain_text)
        
        # Remove any remaining HTML tags
        plain_text = re.sub(r'<[^>]+>', '', plain_text)
        
        # Unescape HTML entities
        plain_text = unescape(plain_text)
        
        # Clean up whitespace
        plain_text = re.sub(r'\n\s*\n\s*\n', '\n\n', plain_text)
        plain_text = plain_text.strip()
        
        return plain_text
    
    def detect_csv_delimiter(self, file_path: str) -> str:
        """Detect CSV delimiter by analyzing the file"""
        with open(file_path, 'r', newline='', encoding='utf-8') as file:
            # Read first few lines to detect delimiter
            sample = file.read(1024)
            file.seek(0)
            
            # Count occurrences of common delimiters
            delimiters = [',', ';', '\t', '|']
            delimiter_counts = {}
            
            for delimiter in delimiters:
                delimiter_counts[delimiter] = sample.count(delimiter)
            
            # Return the delimiter with highest count
            best_delimiter = max(delimiter_counts, key=delimiter_counts.get)
            
            # Fallback to comma if no clear winner
            if delimiter_counts[best_delimiter] == 0:
                return ','
            
            return best_delimiter
    
    def read_emails_from_csv(self, csv_path: str) -> List[Dict[str, str]]:
        """Read email addresses and names from CSV file without pandas"""
        recipients = []
        
        try:
            # Detect delimiter
            delimiter = self.detect_csv_delimiter(csv_path)
            
            with open(csv_path, 'r', newline='', encoding='utf-8') as file:
                # Try different encodings if UTF-8 fails
                try:
                    content = file.read()
                except UnicodeDecodeError:
                    file.seek(0)
                    content = file.read().encode('utf-8', errors='ignore').decode('utf-8')
                
                # Use StringIO to handle the content
                csv_content = io.StringIO(content)
                reader = csv.DictReader(csv_content, delimiter=delimiter)
                
                # Clean up field names (remove whitespace and make lowercase)
                if reader.fieldnames:
                    reader.fieldnames = [field.strip().lower() if field else '' for field in reader.fieldnames]
                
                for row_num, row in enumerate(reader, 1):
                    if not row:  # Skip empty rows
                        continue
                        
                    # Clean up row data
                    clean_row = {}
                    for k, v in row.items():
                        if k:  # Only process non-empty keys
                            clean_row[k.strip().lower()] = v.strip() if v else ''
                    
                    # Try different possible email column names
                    email = None
                    name = None
                    company = None
                    
                    # Look for email in various column names
                    email_columns = ['email', 'email_address', 'mail', 'e-mail', 'emailaddress', 'e_mail']
                    for email_col in email_columns:
                        if email_col in clean_row and clean_row[email_col]:
                            email = clean_row[email_col].strip()
                            break
                    
                    # CRITICAL FIX: Look for name in various column names and handle properly
                    name_columns = ['name', 'full_name', 'firstname', 'first_name', 'recipient', 'fullname', 'full name']
                    for name_col in name_columns:
                        if name_col in clean_row and clean_row[name_col]:
                            name = clean_row[name_col].strip()
                            break
                    
                    # Look for company in various column names
                    company_columns = ['company', 'organization', 'org', 'business', 'company_name']
                    for company_col in company_columns:
                        if company_col in clean_row and clean_row[company_col]:
                            company = clean_row[company_col].strip()
                            break
                    
                    # Validate and add recipient
                    if email and self.validate_email(email):
                        # IMPORTANT: Use the name from CSV or fallback to email prefix
                        display_name = name if name else email.split('@')[0].replace('.', ' ').replace('_', ' ').title()
                        
                        recipients.append({
                            'email': email,
                            'name': display_name,
                            'company': company or ''
                        })
                        self.logger.info(f"Added recipient: {email} (Name: {display_name})")
                    else:
                        self.logger.warning(f"Invalid or missing email in row {row_num}: {email}")
                        
        except Exception as e:
            self.logger.error(f"Error reading CSV file: {str(e)}")
            raise Exception(f"Failed to read email list: {str(e)}")
        
        if not recipients:
            raise Exception("No valid email addresses found in CSV file. Please check the format.")
        
        self.logger.info(f"Successfully loaded {len(recipients)} recipients")
        return recipients
    
    def create_message(self, recipient: Dict[str, str], subject: str, body: str, 
                      attachment_path: Optional[str] = None) -> MIMEMultipart:
        """Create email message with HTML support and optional attachment"""
        
        # Create multipart message with alternative (for HTML and plain text)
        msg = MIMEMultipart('alternative')
        
        # Set headers
        sender_name = self.email.split('@')[0].replace('.', ' ').replace('_', ' ').title()
        msg['From'] = formataddr((sender_name, self.email))
        msg['To'] = formataddr((recipient['name'], recipient['email']))
        msg['Subject'] = subject
        
        # CRITICAL FIX: Smart personalization that doesn't add "Dear" if body already starts with greeting
        personalized_body = body
        
        # Check if body already starts with a greeting
        body_lower = body.lower().strip()
        has_greeting = (body_lower.startswith('dear ') or 
                       body_lower.startswith('hello ') or 
                       body_lower.startswith('hi ') or
                       body_lower.startswith('greetings') or
                       body_lower.startswith('<p>dear ') or
                       body_lower.startswith('<p>hello ') or
                       body_lower.startswith('<p>hi '))
        
        # Only add "Dear {name}," if there's no existing greeting
        if not has_greeting:
            if personalized_body.startswith('<p>'):
                # HTML content - insert after opening <p> tag
                personalized_body = f"<p>Dear {recipient['name']},</p><p><br></p>" + personalized_body
            else:
                # Plain text - add at beginning
                personalized_body = f"Dear {recipient['name']},\n\n" + personalized_body
        
        # Replace personalization tokens
        personalized_body = personalized_body.replace('{name}', recipient['name'])
        personalized_body = personalized_body.replace('{email}', recipient['email'])
        personalized_body = personalized_body.replace('{company}', recipient.get('company', ''))
        
        # Create plain text version
        plain_text_body = self.html_to_plain_text(personalized_body)
        
        # Create both plain text and HTML parts
        text_part = MIMEText(plain_text_body, 'plain', 'utf-8')
        html_part = MIMEText(personalized_body, 'html', 'utf-8')
        
        # Add both parts to message (email clients will choose the best one)
        msg.attach(text_part)
        msg.attach(html_part)
        
        # Add attachment if provided
        if attachment_path and os.path.exists(attachment_path):
            try:
                # Create new multipart message for attachment
                msg_with_attachment = MIMEMultipart('mixed')
                
                # Copy headers
                msg_with_attachment['From'] = msg['From']
                msg_with_attachment['To'] = msg['To']
                msg_with_attachment['Subject'] = msg['Subject']
                
                # Attach the alternative part (HTML + plain text)
                msg_with_attachment.attach(msg)
                
                # Add file attachment
                with open(attachment_path, 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                
                encoders.encode_base64(part)
                filename = os.path.basename(attachment_path)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= "{filename}"'
                )
                msg_with_attachment.attach(part)
                self.logger.info(f"Attached file: {filename}")
                
                return msg_with_attachment
                
            except Exception as e:
                self.logger.error(f"Failed to attach file: {str(e)}")
                # Continue without attachment if it fails
        
        return msg
    
    def send_bulk_emails(self, recipients: List[Dict[str, str]], subject: str, 
                        body: str, attachment_path: Optional[str] = None, 
                        delay: float = 1.0) -> int:
        """Send bulk emails to all recipients with HTML support"""
        
        successful_sends = 0
        failed_sends = 0
        
        try:
            print(f"DEBUG: Connecting to {self.smtp_server}:{self.smtp_port}")
            print(f"DEBUG: Email body type: {type(body)}")
            print(f"DEBUG: Email body preview: {body[:100]}...")
            
            # Establish SMTP connection
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email, self.password)
            
            self.logger.info(f"Starting bulk email send to {len(recipients)} recipients")
            
            for i, recipient in enumerate(recipients, 1):
                try:
                    # Create message with HTML support and smart personalization
                    msg = self.create_message(recipient, subject, body, attachment_path)
                    
                    # Send email
                    text = msg.as_string()
                    server.sendmail(self.email, recipient['email'], text)
                    
                    successful_sends += 1
                    self.logger.info(f"Email {i}/{len(recipients)} sent to {recipient['email']} (Name: {recipient['name']})")
                    print(f"DEBUG: Successfully sent personalized email {i}/{len(recipients)} to {recipient['name']} <{recipient['email']}>")
                    
                    # Add delay to avoid rate limiting
                    if delay > 0 and i < len(recipients):
                        time.sleep(delay)
                        
                except Exception as e:
                    failed_sends += 1
                    self.logger.error(f"Failed to send email to {recipient['email']}: {str(e)}")
                    print(f"DEBUG: Failed to send to {recipient['email']}: {str(e)}")
                    continue
            
            server.quit()
            
        except Exception as e:
            self.logger.error(f"SMTP connection error: {str(e)}")
            raise Exception(f"Failed to establish SMTP connection: {str(e)}")
        
        self.logger.info(f"Bulk email completed. Success: {successful_sends}, Failed: {failed_sends}")
        print(f"DEBUG: Bulk email completed. Success: {successful_sends}, Failed: {failed_sends}")
        
        if successful_sends == 0:
            raise Exception("No emails were sent successfully")
        
        return successful_sends