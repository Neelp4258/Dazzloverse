# Bulk Email Service

A professional Flask-based bulk email application that uses Zoho's SMTP servers to send personalized emails to multiple recipients with file attachments.

## Features

- 🚀 **Easy to Use**: Simple web interface for bulk email sending
- 📧 **Zoho Integration**: Secure SMTP connection with Zoho Mail
- 📎 **File Attachments**: Support for PDF, Word, Excel, and PowerPoint files
- 👥 **Personalization**: Use {name} placeholders for personalized emails
- 📊 **CSV Upload**: Bulk recipient management via CSV files
- 🔒 **Secure**: Form validation, file type checking, and error handling
- 📱 **Responsive**: Modern, mobile-friendly Bootstrap interface
- 🐳 **Docker Ready**: Complete containerization setup

## Quick Start

### Option 1: Local Development

1. **Clone and Setup**
```bash
git clone <repository-url>
cd bulk-email-service
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Configure Environment**
```bash
cp .env.example .env
# Edit .env file with your settings
```

3. **Run the Application**
```bash
python app.py
```

Visit `http://localhost:5000` to start using the service.

### Option 2: Docker Deployment

1. **Simple Docker Run**
```bash
docker build -t bulk-email-service .
docker run -p 5000:5000 bulk-email-service
```

2. **Docker Compose (Recommended)**
```bash
# Development
docker-compose up -d

# Production with Nginx
docker-compose --profile production up -d
```

## Prerequisites

### Zoho Mail Setup

1. **Create Zoho Account**: Sign up at [zoho.com](https://www.zoho.com/mail/)
2. **Enable App Passwords**:
   - Go to Zoho Account Settings → Security → App Passwords
   - Generate a new app password for "Email Clients"
   - Use this app password (not your regular password) in the application

### CSV File Format

Your email list CSV must have the following format:

```csv
email,name
john@company.com,John Doe
jane@company.com,Jane Smith
admin@company.com,Admin User
```

**Required columns:**
- `email`: Valid email addresses
- `name`: Recipient names (used for {name} personalization)

## Usage Guide

### Sending Bulk Emails

1. **Navigate to Send Emails**: Click "Start Sending Emails" from the home page
2. **Enter Credentials**: 
   - Zoho email address
   - Zoho app password (not regular password)
   - Click "Validate Credentials" to test connection
3. **Create Email Content**:
   - Subject line (up to 200 characters)
   - Email body (up to 5000 characters)
   - Use `{name}` for personalization
4. **Upload Files**:
   - **Required**: CSV file with email list
   - **Optional**: Document attachment (PDF, Word, Excel, PowerPoint)
5. **Send**: Review and click "Send Bulk Emails"

### Personalization

Use these placeholders in your email content:
- `{name}`: Replaced with recipient's name from CSV
- `{email}`: Replaced with recipient's email address

Example:
```
Dear {name},

We hope this email finds you well. Your account {email} has been updated...
```

## Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# Flask Configuration
SECRET_KEY=your-very-secret-key-here
FLASK_ENV=development

# File Upload Settings
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=16777216  # 16MB

# Rate Limiting
RATE_LIMIT_EMAILS_PER_MINUTE=10
RATE_LIMIT_EMAILS_PER_HOUR=100
```

### Production Settings

For production deployment:

1. **Set Environment Variables**:
```bash
export FLASK_ENV=production
export SECRET_KEY="your-production-secret-key"
```

2. **Use Gunicorn**:
```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

3. **Configure Nginx** (optional but recommended):
   - Use provided `nginx.conf`
   - Set up SSL certificates
   - Configure domain name

## File Structure

```
bulk-email-service/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── zoho.py               # Zoho SMTP mailer class
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose setup
├── nginx.conf           # Nginx configuration
├── .env.example         # Environment variables template
├── templates/           # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── bulk_mail.html
│   ├── success.html
│   └── error.html
├── uploads/             # Temporary file storage
└── logs/               # Application logs
```

## API Endpoints

- `GET /` - Home page
- `GET/POST /bulk-mail` - Main email sending interface
- `POST /api/validate-email` - Validate Zoho credentials
- `GET /health` - Health check endpoint

## Security Features

- **CSRF Protection**: All forms protected against CSRF attacks
- **File Validation**: Strict file type and size checking
- **Input Sanitization**: All user inputs validated and sanitized
- **Rate Limiting**: Prevents abuse with configurable rate limits
- **Secure Headers**: Security headers included in responses

## Troubleshooting

### Common Issues

1. **"Authentication Failed"**
   - Ensure you're using app password, not regular password
   - Check if two-factor authentication is enabled
   - Verify email address is correct

2. **"No valid email addresses found"**
   - Check CSV format (must have 'email' and 'name' columns)
   - Ensure CSV is properly formatted with commas
   - Remove empty rows from CSV

3. **"File too large"**
   - Maximum file size is 16MB
   - Compress large attachments
   - Split large email lists into smaller batches

4. **Connection Timeout**
   - Check internet connection
   - Verify Zoho SMTP settings
   - Try reducing batch size

### Logs

Application logs are stored in `logs/app.log` and include:
- Email sending status
- Error messages
- File upload information
- Authentication attempts

## Deployment Options

### 1. Traditional Server

```bash
# Install dependencies
pip install -r requirements.txt

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

### 2. Docker

```bash
# Build and run
docker build -t bulk-email-service .
docker run -p 5000:5000 bulk-email-service
```

### 3. Cloud Platforms

**Heroku:**
```bash
# Add Procfile
echo "web: gunicorn app:app" > Procfile
git push heroku main
```

**DigitalOcean/AWS/GCP:**
- Use provided Dockerfile
- Configure environment variables
- Set up load balancer if needed

## Performance Considerations

- **Email Rate Limiting**: 1-second delay between emails to prevent blocking
- **File Cleanup**: Uploaded files automatically deleted after sending
- **Memory Usage**: Large email lists processed in batches
- **Logging**: Configurable log levels for production

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review application logs
3. Open an issue on GitHub
4. Contact support team

## Changelog

### v1.0.0
- Initial release
- Basic bulk email functionality
- Zoho SMTP integration
- File attachment support
- Docker containerization
- Web interface with Bootstrap