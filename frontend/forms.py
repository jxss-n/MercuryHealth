from django import forms
import datetime
from django.utils import timezone


class BetaForm(forms.Form):
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    email = forms.CharField(required=True)
    phone_number = forms.CharField(required=True)
    short_answer1 = forms.CharField(required=True)
    short_answer2 = forms.CharField(required=True)
    short_answer3 = forms.CharField(required=True)

class LoginForm(forms.Form):
    username = forms.CharField(required=True)
    password = forms.CharField(required=True, widget=forms.PasswordInput)


class RegisterForm(forms.Form):
    password = forms.CharField(required=True, widget=forms.PasswordInput)
    confirm_password = forms.CharField(required=True, widget=forms.PasswordInput)
    #email = forms.EmailField(required=True)
    username = forms.CharField(required=True)
    #device_id = forms.CharField(required=True)


class forgotPasswordForm(forms.Form):
    email = forms.EmailField(required=True)

class resetPasswordForm(forms.Form):
    confirmationCode = forms.CharField(required=True)
    #email = forms.EmailField(required=True)
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
