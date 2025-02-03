from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import CustomUser
from django.db.models import Q
from .forms import CustomUserCreationForm, CustomAuthenticationForm, CustomPasswordChangeForm, ForgotPasswordForm, ResetPasswordForm
from django.contrib.auth import update_session_auth_hash, password_validation
from django.urls import reverse
from django.core.mail import EmailMessage
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

@login_required
def dashboard(request):
    return render(request, 'users/index.html', {
        'username': request.user.username
    })

# Login view with email or username
def login_view(request):
    if request.method == "POST":
        form = CustomAuthenticationForm(request.POST)
        if form.is_valid():
            user_input = form.cleaned_data['Email_or_Password']
            password = form.cleaned_data['password']
            print("29")

            try:
                # Look for the user using either email or username
                user = CustomUser.objects.get(Q(email=user_input) | Q(username=user_input))
                email = user.email  # Use username for authentication
                print("35")

            except CustomUser.DoesNotExist:
                messages.error(request, 'Invalid credentials')
                print("39")

                return redirect('login')


            # Authenticate the user
            authenticated_user = authenticate(request, email=email, password=password)

            if authenticated_user:
                print("48")

                login(request, authenticated_user)
                return redirect('dashboard')  # Redirect to dashboard after successful login
            else:
                messages.error(request, 'Invalid credentials')
                return redirect('login')

    else:
        form = CustomAuthenticationForm()

    return render(request, 'users/login.html', {'form': form})


# Sign up view
def signup_view(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Account created. You can now log in.')
            return redirect('login')
        else:
            for error in form.errors:
                messages.error(request, form.errors[error])
            return redirect('signup')
    else:
        form = CustomUserCreationForm()

    return render(request, 'users/signup.html', {'form': form})


@login_required
def logout_view(request):
    logout(request)
    return redirect('login')


@login_required
def profile_view(request):
    user = request.user
    return render(request, 'users/profile.html', {
        'user': user,
        'joined': user.date_joined,
        'last_login': user.last_login
    })


@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            messages.success(request, 'Password updated successfully!')
            return redirect('profile')
        else:
            messages.error(request, 'Please fix the errors below.')
    else:
        form = CustomPasswordChangeForm(user=request.user)

    return render(request, 'users/change_password.html', {'form': form})


def forgot_password_view(request):
    if request.method == "POST":
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            try:
                user = CustomUser.objects.get(email=email)

                # Generate password reset token and uid
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(str(user.pk).encode())

                reset_url = reverse('reset-password', kwargs={'uidb64': uid, 'token': token})
                full_reset_url = f'{request.scheme}://{request.get_host()}{reset_url}'

                # Send the reset email
                email_body = f'Click to reset your password:\n\n{full_reset_url}'
                email_message = EmailMessage(
                    'Reset your password',
                    email_body,
                    settings.EMAIL_HOST_USER,
                    [email]
                )
                email_message.fail_silently = True
                email_message.send()

                messages.success(request, 'Password reset instructions sent to your email.')
                return redirect('password-reset-sent')

            except CustomUser.DoesNotExist:
                messages.error(request, f"No account found with email '{email}'")
                return redirect('forgot-password')
    else:
        form = ForgotPasswordForm()

    return render(request, 'users/forgot_password.html', {'form': form})


def password_reset_sent_view(request):
    return render(request, 'users/password_reset_sent.html')


def reset_password_view(request, uidb64, token):
    try:
        # Decode the uid and retrieve the user
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)

        # Check if the token is valid
        if default_token_generator.check_token(user, token):
            if request.method == "POST":
                form = ResetPasswordForm(request.POST)
                if form.is_valid():
                    password = form.cleaned_data['password']
                    confirm_password = form.cleaned_data['confirm_password']

                    if password != confirm_password:
                        messages.error(request, 'Passwords do not match')
                    elif len(password) < 6:
                        messages.error(request, 'Password must be at least 6 characters')
                    else:
                        # Update user password
                        user.set_password(password)
                        user.save()

                        messages.success(request, 'Password reset successful. You can now log in.')
                        return redirect('login')

            else:
                form = ResetPasswordForm()

            return render(request, 'users/reset_password.html', {'form': form})
        else:
            messages.error(request, 'Invalid or expired reset link')
            return redirect('forgot-password')

    except CustomUser.DoesNotExist:
        messages.error(request, 'Invalid reset link')
        return redirect('forgot-password')
