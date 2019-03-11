from django import forms
import datetime
from django.utils import timezone


class LoginForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(required=True, widget=forms.PasswordInput)


class RegisterForm(forms.Form):
    password = forms.CharField(required=True, widget=forms.PasswordInput)
    email = forms.EmailField(required=True)
    name = forms.CharField(required=True)
    device_id = forms.CharField(required=True)


class forgotPasswordForm(forms.Form):
    email = forms.EmailField(required=True)

class resetPasswordForm(forms.Form):
    confirmationCode = forms.CharField(required=True)
    email = forms.EmailField(required=True)
    newPassword = forms.CharField(required=True, widget=forms.PasswordInput)

class emergencyContactForm(forms.Form):
    Name = forms.CharField(required=True)
    Number =  forms.CharField(required=True, max_length=12)
    Name2 = forms.CharField(required=True)
    Number2 =  forms.CharField(required=True, max_length=12)
    Name3 = forms.CharField(required=True)
    Number3 =  forms.CharField(required=True, max_length=12)
