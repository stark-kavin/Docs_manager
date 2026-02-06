from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from django.conf import settings
import resend

def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
    """Generate encryption key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file_data(file_data: bytes, key: bytes) -> bytes:
    """Encrypt file data using Fernet symmetric encryption"""
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)
    return encrypted_data

def decrypt_file_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt file data using Fernet symmetric encryption"""
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data

def generate_user_key(user_id: int) -> str:
    """Generate a unique encryption key for each user"""
    password = f"user_{user_id}_{settings.SECRET_KEY}"
    key, _ = generate_key_from_password(password)
    return key.decode()

def get_user_encryption_key(user_id: int) -> bytes:
    """Get encryption key for a user"""
    key_str = generate_user_key(user_id)
    return key_str.encode()

# Email utility functions
def send_otp_email(email: str, otp_code: str) -> bool:
    """
    Send OTP code via email using Resend service

    Args:
        email (str): Recipient email address
        otp_code (str): OTP code to send

    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        # Initialize Resend client
        resend.api_key = settings.RESEND_API_KEY

        # Create HTML email template
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Secure Drive - OTP Verification</title>
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0;">
                <h1 style="margin: 0; font-size: 24px;">🔒 Secure Drive</h1>
                <p style="margin: 10px 0 0 0; opacity: 0.9;">Email Verification</p>
            </div>

            <div style="background: white; border: 1px solid #e5e7eb; border-radius: 0 0 10px 10px; padding: 30px;">
                <h2 style="color: #1f2937; margin-top: 0;">Your Verification Code</h2>

                <p style="color: #6b7280; line-height: 1.6;">
                    Hello! You've requested to sign in to your Secure Drive account.
                    Please use the verification code below to complete your login:
                </p>

                <div style="background: #f9fafb; border: 2px solid #4f46e5; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
                    <div style="font-size: 32px; font-weight: bold; color: #4f46e5; letter-spacing: 4px;">
                        {otp_code}
                    </div>
                </div>

                <p style="color: #6b7280; font-size: 14px;">
                    This code will expire in {settings.OTP_EXPIRY_MINUTES} minutes for security reasons.
                    If you didn't request this code, please ignore this email.
                </p>

                <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">

                <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                    Secure Drive - Your encrypted file storage solution<br>
                    If you have any questions, please contact our support team.
                </p>
            </div>
        </body>
        </html>
        """

        # Send email using Resend
        response = resend.Emails.send({
            "from": settings.EMAIL_FROM,
            "to": email,
            "subject": f"Secure Drive - Your Verification Code: {otp_code}",
            "html": html_content
        })

        return bool(response and response.get('id'))

    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False