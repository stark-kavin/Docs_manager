from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, StreamingHttpResponse, Http404
from django.core.files.base import ContentFile
from django.views.decorators.http import require_POST
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from .models import Folder, File, EmailOTP
from .utils import encrypt_file_data, decrypt_file_data, get_user_encryption_key, send_otp_email
import mimetypes
import os

def login_view(request):
    """Email OTP login view"""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()

        if not email:
            messages.error(request, 'Please enter your email address.')
            return render(request, 'drive/login.html')

        try:
            # Validate email format
            from django.core.validators import validate_email
            validate_email(email)

            # Check if user exists or create one
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0] + str(User.objects.filter(email=email).count() + 1),
                    'first_name': email.split('@')[0],
                }
            )

            # Create OTP
            otp_obj = EmailOTP.create_otp(email)

            # Send OTP email
            if send_otp_email(email, otp_obj.otp_code):
                messages.success(request, f'OTP sent to {email}. Please check your email.')
                request.session['otp_email'] = email
                return redirect('verify_otp')
            else:
                messages.error(request, 'Failed to send OTP. Please try again.')
                return render(request, 'drive/login.html')

        except ValidationError:
            messages.error(request, 'Please enter a valid email address.')
            return render(request, 'drive/login.html')
        except Exception as e:
            messages.error(request, 'An error occurred. Please try again.')
            return render(request, 'drive/login.html')

    return render(request, 'drive/login.html')

def verify_otp_view(request):
    """OTP verification view"""
    if request.user.is_authenticated:
        return redirect('dashboard')

    email = request.session.get('otp_email')
    if not email:
        messages.error(request, 'Session expired. Please start login again.')
        return redirect('login')

    if request.method == 'POST':
        otp_code = request.POST.get('otp', '').strip()

        if not otp_code:
            messages.error(request, 'Please enter the OTP code.')
            return render(request, 'drive/verify_otp.html', {'email': email})

        try:
            # Get the latest unused OTP for this email
            otp_obj = EmailOTP.objects.filter(
                email=email,
                is_used=False
            ).latest('created_at')

            if otp_obj.verify_otp(otp_code):
                # OTP verified successfully
                try:
                    user = User.objects.get(email=email)
                    login(request, user)
                    del request.session['otp_email']

                    # Clean up used OTPs
                    EmailOTP.objects.filter(email=email, is_used=True).delete()

                    messages.success(request, f'Welcome back, {user.first_name or user.username}!')
                    return redirect('dashboard')
                except User.DoesNotExist:
                    messages.error(request, 'User account not found.')
                    return redirect('login')
            else:
                if otp_obj.attempts >= 3:
                    messages.error(request, 'Too many failed attempts. Please request a new OTP.')
                    return redirect('login')
                else:
                    messages.error(request, f'Invalid OTP code. {3 - otp_obj.attempts} attempts remaining.')

        except EmailOTP.DoesNotExist:
            messages.error(request, 'OTP code not found or expired. Please request a new OTP.')
            return redirect('login')

    return render(request, 'drive/verify_otp.html', {'email': email})

def resend_otp_view(request):
    """Resend OTP view"""
    if request.user.is_authenticated:
        return redirect('dashboard')

    email = request.session.get('otp_email')
    if not email:
        messages.error(request, 'Session expired. Please start login again.')
        return redirect('login')

    try:
        # Check if we can resend (prevent spam)
        recent_otps = EmailOTP.objects.filter(
            email=email,
            created_at__gte=timezone.now() - timezone.timedelta(minutes=1)
        ).count()

        if recent_otps >= 2:
            messages.error(request, 'Please wait before requesting another OTP.')
            return redirect('verify_otp')

        # Create new OTP
        otp_obj = EmailOTP.create_otp(email)

        # Send OTP email
        if send_otp_email(email, otp_obj.otp_code):
            messages.success(request, f'New OTP sent to {email}.')
        else:
            messages.error(request, 'Failed to send OTP. Please try again.')

    except Exception as e:
        messages.error(request, 'An error occurred. Please try again.')

    return redirect('verify_otp')

@login_required
def dashboard(request):
    """Main dashboard showing root folder contents"""
    root_folders = Folder.objects.filter(owner=request.user, parent=None)
    root_files = File.objects.filter(owner=request.user, folder=None)
    
    context = {
        'folders': root_folders,
        'files': root_files,
        'current_folder': None,
        'breadcrumb': []
    }
    return render(request, 'drive/dashboard.html', context)

@login_required
def folder_view(request, folder_id):
    """View contents of a specific folder"""
    folder = get_object_or_404(Folder, id=folder_id, owner=request.user)
    
    subfolders = folder.subfolders.all()
    files = folder.files.all()
    
    # Build breadcrumb
    breadcrumb = []
    current = folder
    while current:
        breadcrumb.insert(0, current)
        current = current.parent
    
    context = {
        'folders': subfolders,
        'files': files,
        'current_folder': folder,
        'breadcrumb': breadcrumb
    }
    return render(request, 'drive/dashboard.html', context)

@login_required
@require_POST
def create_folder(request):
    """Create a new folder"""
    name = request.POST.get('name')
    parent_id = request.POST.get('parent_id')
    
    if not name:
        messages.error(request, 'Folder name is required')
        return redirect('dashboard')
    
    parent = None
    if parent_id:
        parent = get_object_or_404(Folder, id=parent_id, owner=request.user)
    
    if Folder.objects.filter(owner=request.user, parent=parent, name=name).exists():
        messages.error(request, 'A folder with this name already exists')
    else:
        Folder.objects.create(name=name, parent=parent, owner=request.user)
        messages.success(request, 'Folder created successfully')
    
    if parent:
        return redirect('folder_view', folder_id=parent.id)
    return redirect('dashboard')

@login_required
@require_POST
def upload_file(request):
    """Upload and encrypt a file"""
    uploaded_file = request.FILES.get('file')
    folder_id = request.POST.get('folder_id')
    
    if not uploaded_file:
        messages.error(request, 'No file selected')
        if folder_id:
            return redirect('folder_view', folder_id=int(folder_id))
        else:
            return redirect('dashboard')
    
    folder = None
    if folder_id:
        folder = get_object_or_404(Folder, id=folder_id, owner=request.user)
    
    # Check if file already exists
    if File.objects.filter(owner=request.user, folder=folder, name=uploaded_file.name).exists():
        messages.error(request, 'A file with this name already exists')
        if folder:
            return redirect('folder_view', folder_id=folder.id)
        else:
            return redirect('dashboard')
    
    # Read and encrypt file data
    file_data = uploaded_file.read()
    encryption_key = get_user_encryption_key(request.user.id)
    encrypted_data = encrypt_file_data(file_data, encryption_key)
    
    # Save encrypted file
    file_name = f"encrypted_{uploaded_file.name}"
    file_instance = File(
        name=uploaded_file.name,
        folder=folder,
        owner=request.user,
        original_size=len(file_data),
        file_type=mimetypes.guess_type(uploaded_file.name)[0] or 'application/octet-stream',
        encryption_key=encryption_key.decode()
    )
    file_instance.encrypted_file.save(file_name, ContentFile(encrypted_data))
    
    messages.success(request, 'File uploaded successfully')
    if folder:
        return redirect('folder_view', folder_id=folder.id)
    else:
        return redirect('dashboard')

@login_required
def download_file(request, file_id):
    """Stream decrypted file for download"""
    file_obj = get_object_or_404(File, id=file_id, owner=request.user)
    
    try:
        # Read encrypted file
        encrypted_data = file_obj.encrypted_file.read()
        
        # Decrypt file data
        encryption_key = file_obj.encryption_key.encode()
        decrypted_data = decrypt_file_data(encrypted_data, encryption_key)
        
        # Create streaming response
        response = StreamingHttpResponse(
            iter([decrypted_data]),
            content_type=file_obj.file_type
        )
        
        # Set headers for download
        response['Content-Disposition'] = f'attachment; filename="{file_obj.name}"'
        response['Content-Length'] = file_obj.original_size
        
        return response
        
    except Exception as e:
        messages.error(request, 'Error downloading file')
        return redirect('dashboard')

@login_required
@require_POST
def delete_file(request, file_id):
    """Delete a file"""
    file_obj = get_object_or_404(File, id=file_id, owner=request.user)
    folder = file_obj.folder
    
    # Delete encrypted file from storage
    if file_obj.encrypted_file:
        file_obj.encrypted_file.delete()
    
    file_obj.delete()
    messages.success(request, 'File deleted successfully')
    
    if folder:
        return redirect('folder_view', folder_id=folder.id)
    else:
        return redirect('dashboard')

@login_required
@require_POST
def delete_folder(request, folder_id):
    """Delete a folder and all its contents"""
    folder = get_object_or_404(Folder, id=folder_id, owner=request.user)
    parent = folder.parent
    
    # Delete all files in folder and subfolders
    def delete_folder_contents(folder):
        # Delete files
        for file_obj in folder.files.all():
            if file_obj.encrypted_file:
                file_obj.encrypted_file.delete()
            file_obj.delete()
        
        # Recursively delete subfolders
        for subfolder in folder.subfolders.all():
            delete_folder_contents(subfolder)
            subfolder.delete()
    
    delete_folder_contents(folder)
    folder.delete()
    messages.success(request, 'Folder deleted successfully')
    
    if parent:
        return redirect('folder_view', folder_id=parent.id)
    else:
        return redirect('dashboard')
