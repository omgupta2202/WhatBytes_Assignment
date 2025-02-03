# User Authentication Dashboard

## Overview

A Django-based user authentication system with features like login, signup, password reset, profile management, and a personalized dashboard.

---

## Features

- **Authentication**: Login, Signup, Forgot Password, Reset Password, Change Password
- **Profile Management**: View and update user profile.
- **Dashboard**: Displays user stats and personalized greeting.
- **Responsive UI**: Clean, responsive design with modern UI elements.

---

## Setup Instructions

### Prerequisites
- Python 3.8+
- Django 5.1.5+

### Steps to Run

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/yourrepository.git
   cd yourrepository
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # For Linux/macOS
   .venv\Scripts\activate  # For Windows
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Apply migrations**:
   ```bash
   python manage.py migrate
   ```

5. **Create superuser**:
   ```bash
   python manage.py createsuperuser
   ```

6. **Run the server**:
   ```bash
   python manage.py runserver
   ```

7. **Access the app** at `http://127.0.0.1:8000/`.

---

## URLs

- `/login/`: Login page
- `/signup/`: Signup page
- `/logout/`: Logout
- `/dashboard/`: User dashboard
- `/profile/`: User profile
- `/change-password/`: Change password
- `/forgot-password/`: Forgot password

---

## Template Structure

- **login.html**: Login form
- **signup.html**: Signup form
- **profile.html**: User profile page
- **change_password.html**: Change password form
- **forgot_password.html**: Forgot password form
- **reset_password.html**: Password reset form
- **dashboard.html**: User dashboard

---

## Custom User Model

This project uses a **CustomUser** model with email-based authentication:

```python
class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
```
