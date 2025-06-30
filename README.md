# Dazzloverse - Professional Bulk Email Platform

A powerful and secure bulk email platform built with Python Flask, designed for businesses to send personalized email campaigns efficiently.

## Features

- 🚀 Send bulk emails with personalization
- 📊 Campaign analytics and tracking
- 📁 CSV contact list support
- 📎 File attachment support
- 🎨 Rich text editor
- 🔒 Secure SMTP integration
- 📱 Responsive design
- 👥 User management
- 📈 Usage tracking
- 💰 Multiple pricing plans

## Plans and Limits

1. Free Plan:
   - 1,000 emails per day
   - Basic templates
   - CSV upload support
   - File attachments (16MB)
   - Email support

2. Basic Plan (₹2,000/month):
   - 200 emails per day
   - Custom templates
   - Priority support
   - Advanced personalization

3. Professional Plan (₹3,000/month):
   - 500 emails per day
   - Email analytics
   - A/B testing
   - Custom CSS support
   - Dedicated support

4. Enterprise Plan (₹5,000/month):
   - 1,000 emails per day
   - API access
   - White-label solution
   - Custom integrations
   - 24/7 phone support

## Tech Stack

- Backend: Python Flask
- Database: SQLite
- Frontend: HTML, CSS, JavaScript
- UI Framework: Bootstrap 5
- Icons: Font Awesome
- Email: SMTP Integration

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/Neelp4258/Dazzloverse.git
   cd Dazzloverse
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Initialize the database:
   ```bash
   flask init-database
   ```

4. Create admin user:
   ```bash
   flask create-admin
   ```

5. Run the application:
   ```bash
   python app.py
   ```

6. Visit http://localhost:5000 in your browser

## Environment Setup

Create a `.env` file in the root directory with the following variables:
```
FLASK_SECRET_KEY=your-secret-key
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=16777216
```

## Project Structure

```
Dazzloverse/
├── app.py              # Main application file
├── emailer.py          # Email handling logic
├── requirements.txt    # Python dependencies
├── static/            # Static assets
├── templates/         # HTML templates
├── uploads/           # File uploads
└── logs/              # Application logs
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, email info@dazzlo.co.in or call +91 9373015503.

## Demo Credentials

- Admin Panel: admin / dazzlo2025
- Demo User: demo@dazzlo.co.in / demo123 