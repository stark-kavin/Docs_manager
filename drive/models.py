from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import os
import random
import string

class Folder(models.Model):
    name = models.CharField(max_length=255)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='subfolders')
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['name', 'parent', 'owner']
    
    def __str__(self):
        return self.name
    
    def get_path(self):
        if self.parent:
            return os.path.join(self.parent.get_path(), self.name)
        return self.name

class File(models.Model):
    name = models.CharField(max_length=255)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, null=True, blank=True, related_name='files')
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_file = models.FileField(upload_to='encrypted_files/')
    original_size = models.PositiveIntegerField()
    file_type = models.CharField(max_length=100)
    encryption_key = models.CharField(max_length=255)  # Store encrypted key
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['name', 'folder', 'owner']

    def __str__(self):
        return self.name

    @property
    def icon(self):
        """Returns an emoji icon based on the file MIME type."""
        if not self.file_type:
            return '📄'
        
        file_type = self.file_type.lower()
        
        if 'image' in file_type:
            return '🖼️'
        if 'pdf' in file_type:
            return '📕'
        if 'text' in file_type or 'json' in file_type or 'xml' in file_type:
            return '📝'
        if 'word' in file_type or 'document' in file_type or 'msword' in file_type:
            return '📘'
        if 'excel' in file_type or 'sheet' in file_type or 'csv' in file_type:
            return '📊'
        if 'powerpoint' in file_type or 'presentation' in file_type:
            return '📙'
        if 'zip' in file_type or 'rar' in file_type or 'compressed' in file_type or 'tar' in file_type:
            return '📦'
        if 'audio' in file_type:
            return '🎵'
        if 'video' in file_type:
            return '🎬'
        if 'python' in file_type or 'x-python' in file_type:
            return '🐍'
            
        return '📄'

class EmailOTP(models.Model):
    email = models.EmailField()
    otp_code = models.CharField(max_length=10)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)

    class Meta:
        verbose_name = 'Email OTP'
        verbose_name_plural = 'Email OTPs'

    def __str__(self):
        return f"{self.email} - {self.otp_code}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @classmethod
    def generate_otp(cls, length=6):
        """Generate a random OTP code"""
        return ''.join(random.choices(string.digits, k=length))

    @classmethod
    def create_otp(cls, email):
        """Create a new OTP for the given email"""
        from django.conf import settings

        otp_code = cls.generate_otp(settings.OTP_LENGTH)
        expires_at = timezone.now() + timezone.timedelta(minutes=settings.OTP_EXPIRY_MINUTES)

        # Deactivate any existing OTPs for this email
        cls.objects.filter(email=email, is_used=False).update(is_used=True)

        return cls.objects.create(
            email=email,
            otp_code=otp_code,
            expires_at=expires_at
        )

    def verify_otp(self, code):
        """Verify the OTP code"""
        if self.is_used or self.is_expired:
            return False

        if self.otp_code == code:
            self.is_used = True
            self.save()
            return True

        self.attempts += 1
        self.save()
        return False
