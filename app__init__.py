from flask_mail import Mail
import os

# Create these objects at module level
mail = Mail()  # Initialize mail here but don't configure it yet

# Configure mail settings

# Make sure to export mail
__all__ = ['db', 'login_manager', 'mail']  # Include other exports as needed
