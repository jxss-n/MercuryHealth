from django import forms
import datetime
from django.utils import timezone


class LoginForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(required=True, widget=forms.PasswordInput)


class RegisterForm(forms.Form):
    password = forms.CharField(required=True, widget=forms.PasswordInput)
    confirm_password = forms.CharField(required=True, widget=forms.PasswordInput)
    email = forms.EmailField(required=True)
    name = forms.CharField(required=True)
    #device_id = forms.CharField(required=True)


class forgotPasswordForm(forms.Form):
    email = forms.EmailField(required=True)

class resetPasswordForm(forms.Form):
    confirmationCode = forms.CharField(required=True)
    email = forms.EmailField(required=True)
    newPassword = forms.CharField(required=True, widget=forms.PasswordInput)

class emergencyContactForm(forms.Form):
    Name = forms.CharField(required=False)
    Number =  forms.CharField(required=False, max_length=12)
    Relationship = forms.CharField(required=False)
    Name2 = forms.CharField(required=False)
    Number2 =  forms.CharField(required=False, max_length=12)
    Relationship2 = forms.CharField(required=False)
    Name3 = forms.CharField(required=False)
    Number3 =  forms.CharField(required=False, max_length=12)
    Relationship3 = forms.CharField(required=False)
    Name4 = forms.CharField(required=False)
    Number4 =  forms.CharField(required=False, max_length=12)
    Relationship4 = forms.CharField(required=False)
    Name5 = forms.CharField(required=False)
    Number5 =  forms.CharField(required=False, max_length=12)
    Relationship5 = forms.CharField(required=False)
