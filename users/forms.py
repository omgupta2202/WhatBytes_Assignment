from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from .models import CustomUser


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError(_("A user with this email already exists."))
        return email


class CustomAuthenticationForm(forms.Form):
    Email_or_Password = forms.CharField(max_length=255, required=True, widget=forms.TextInput(attrs={'placeholder': 'Username or Email'}))
    password = forms.CharField(required=True, widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))

    def clean_identifier(self):
        Email_or_Password = self.cleaned_data.get('Email_or_Password')
        if not Email_or_Password:
            raise ValidationError(_("This field is required."))
        return Email_or_Password


class CustomPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(widget=forms.PasswordInput, required=True)
    new_password1 = forms.CharField(widget=forms.PasswordInput, required=True)
    new_password2 = forms.CharField(widget=forms.PasswordInput, required=True)

    class Meta:
        model = CustomUser
        fields = ['old_password', 'new_password1', 'new_password2']

    def clean_new_password2(self):
        new_password1 = self.cleaned_data.get('new_password1')
        new_password2 = self.cleaned_data.get('new_password2')

        if new_password1 != new_password2:
            raise ValidationError(_("The two password fields didn't match."))

        return new_password2


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField()

    def clean_email(self):
        email = self.cleaned_data.get('email')

        # Query CustomUser model instead of the default CustomUser model
        if not CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("No account found with this email.")

        return email


class ResetPasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'New password'}), required=True)
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Confirm password'}), required=True)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password != confirm_password:
            raise ValidationError(_("The two password fields didn't match."))

        if len(password) < 6:
            raise ValidationError(_("Password must be at least 6 characters."))

        return cleaned_data
