from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('dashboard/', login_required(views.dashboard), name='dashboard'),  # Use the login_required decorator here
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('change-password/', views.change_password_view, name='change-password'),
    path('forgot-password/', views.forgot_password_view, name='forgot-password'),
    path('password-reset-sent/', views.password_reset_sent_view, name='password-reset-sent'),
    path('reset-password/<str:uidb64>/<str:token>/', views.reset_password_view, name='reset-password'),
]
