from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('folder/<int:folder_id>/', views.folder_view, name='folder_view'),
    path('create-folder/', views.create_folder, name='create_folder'),
    path('upload/', views.upload_file, name='upload_file'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),
    path('delete-file/<int:file_id>/', views.delete_file, name='delete_file'),
    path('delete-folder/<int:folder_id>/', views.delete_folder, name='delete_folder'),
    path('login/', views.login_view, name='login'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('resend-otp/', views.resend_otp_view, name='resend_otp'),
]