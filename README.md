# Secure Online Storage System

A Flask-based web application for secure file storage with client-side encryption, access control, and audit logging.

## Features
- User authentication with password hashing
- Client-side file encryption before upload
- Secure file sharing with permissions
- Activity auditing and logging
- Role-based access control
- Secure file deletion with overwrite

## Requirements
- Python 3.9+
- MySQL/MariaDB
- XAMPP (for local MySQL server)

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/secure-storage-system.git
cd secure-storage-system
```

### 2. Create Virtual Environment (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate  # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup
1. Start XAMPP and run MySQL server
2. import online_storage.sql


## Running the Application
### 1. Start Development Server
```bash
python run.py
```

### 2. Access Application
Open in browser:
[http://localhost:5000/login](http://localhost:5000/login)