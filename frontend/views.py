from django.shortcuts import render
from django import forms
from django.http import HttpResponse
from django.http import JsonResponse
from django.contrib.auth import logout
#from .forms import JobForm
from django.template import RequestContext
#import json
#from django.shortcuts import HttpResponseRedirect
#from django.core.urlresolvers import reverse
from .forms import *
from django.contrib.auth import hashers
from django.contrib import messages
from django.shortcuts import render_to_response
from django.utils import timezone
from django.template import loader
import requests
import json
from django.shortcuts import HttpResponseRedirect
from django.urls import reverse
import datetime

ERROR_FILL_OUT = "Please fill out all fields"
ERROR_OBTAIN_DATA = "Coudln't obtain your data. Please contact"
ERROR_OBTAIN_EMERGENCY_SEND = "Coudln't send the emergency data"
ERROR_TOKEN_SEND = "Coudn't send tokens please contact us"
ERROR_SIGNUP = "Invalid email or Password"
ERROR_DEVICE = "DeviceID not found"
ERROR_USEREXISTS = "user already exists"
class IP(object):
    def __init__(self):
        self._address = None

    @property
    def address(self):
        """I'm the 'address' property."""
        print("getter of address called")
        return self._address

    @address.setter
    def address(self, value):
        print("setter of address called")
        self._address = value

    @address.deleter
    def address(self):
        print("deleter of address called")
        del self._address
ip = IP()
# Create your views here.
def index(request):
    auth = request.COOKIES.get('auth')
    try:
        errorMessage = request.session['errorMessage']
        cred = request.session['cred']
        print(cred)
    except Exception as e:
        errorMessage = None
        cred = None
    if errorMessage != None and cred == 'login':
        print(errorMessage)
        del request.session['errorMessage']
        del request.session['cred']
        print(cred)
        return render(request, 'frontend/index.html', {'auth': auth, 'errorMessage': errorMessage, 'cred': cred})
    elif errorMessage != None and cred == 'signup':
        print(errorMessage)
        del request.session['errorMessage']
        del request.session['cred']
        print(cred)
        return render(request, 'frontend/index.html', {'auth': auth, 'errorMessage': errorMessage, 'cred': cred})
    return render(request, 'frontend/index.html', {'auth': auth, 'errorMessage': None})

def verify(request):
    auth = request.COOKIES.get('auth')
    return render(request, 'frontend/verify.html')


def user_page(request):
    #use the comma to set a default auth variable
    auth = request.COOKIES.get('auth')
    try:
        errorMessage = request.session['errorMessage']
        cred = request.session['cred']
        print(cred)
    except Exception as e:
        errorMessage = None
        cred = None
    if errorMessage != None and cred == 'forgot-password':
        print(errorMessage)
        del request.session['errorMessage']
        del request.session['cred']
        print(cred)
        return render(request, 'frontend/user_page.html', {'auth': auth, 'errorMessage': errorMessage, 'cred': cred})
    elif errorMessage != None and cred == 'reset_password':
        print(errorMessage)
        del request.session['errorMessage']
        del request.session['cred']
        print(cred)
        return render(request, 'frontend/user_page.html', {'auth': auth, 'errorMessage': errorMessage, 'cred': cred})
    if auth:
        auth = auth.replace("'", '"')
        auth = json.loads(auth)
        email = auth["email"]

    #TODO change the ipaddress to cookies
    #TODO auth = request.COOKIES.get('auth', 'somedefaultvalue') - if its default then do something else
        #try:
            #print("it is working 1")
            #if request.session['ip_address']:
                #refresh_token = auth["RefreshToken"]
                #id_token = auth["token"]
                #access_token =  auth['AccessToken']
        #send all the data to the device
        #TODO going to use the cookie instead.
                #del request.session['ip_address']
        #except Exception as e:
            #pass
        try:
            print("it is working 2")
            print(auth['AccessToken'])
            user_data_response = requests.get("https://kayxrpz2ef.execute-api.us-west-2.amazonaws.com/production/data", params = {"AccessToken": auth['AccessToken']}, headers = {"Authorization": auth["token"]})
            print(user_data_response)
        except Exception as e:
            return render( request, 'frontend/user_page.html', {'message': ERROR_OBTAIN_DATA})
        try:
            User_Analytics = requests.get("https://mwnpu1mot0.execute-api.us-west-2.amazonaws.com/Production/user-analytics", params = {"AccessToken": auth['AccessToken']}, headers = {"Authorization": auth["token"]})
        except Exception as e:
            return render( request, 'frontend/user_page.html', {'message': ERROR_OBTAIN_DATA})
        user_data_response = json.loads(user_data_response.content)
        user_analytics_response = json.loads(User_Analytics.content)
        print(user_analytics_response)
        print(user_data_response)
        if 'status' in user_data_response and 'status' in user_analytics_response:
            if user_data_response['status'] == 'Success':
                print("it is working 3")
                content = user_data_response['emergency_contacts']
                print(content)
                if request.method == 'GET':
                    if content == "not set":
                        return render(request, 'frontend/user_page.html', {'email': email, 'message': content})
                    else:
                        #make the field here dynamic
                        return render(request, 'frontend/user_page.html', {'message': 'contact saved',
                        'email': email,
                        'name': content['name'],
                        'name2': content['name2'],
                        'name3': content['name3'],
                        'name4': content['name4'],
                        'name5': content['name5'],
                        'number': content['number'],
                        'number2': content['number2'],
                        'number3': content['number3'],
                        'number4': content['number4'],
                        'number5': content['number5'],
                        'relationship':content['relationship'],
                        'relationship2':content['relationship2'],
                        'relationship3':content['relationship3'],
                        'relationship4':content['relationship4'],
                        'relationship5':content['relationship5']
                        })
                f = emergencyContactForm(request.POST)
                print(f.is_valid())
                print(f)
                print("I contactform")
                if f.is_valid():
                    name = f.cleaned_data['Name'] or 'not set'
                    number = f.cleaned_data['Number'] or 'not set'
                    relationship = f.cleaned_data['Relationship'] or 'not set'

                    name2 = f.cleaned_data['Name2'] or 'not set'
                    number2 = f.cleaned_data['Number2'] or 'not set'
                    relationship2 = f.cleaned_data['Relationship2'] or 'not set'
                    print(name)

                    name3 = f.cleaned_data['Name3'] or 'not set'
                    number3 = f.cleaned_data['Number3'] or 'not set'
                    relationship3 = f.cleaned_data['Relationship3'] or 'not set'

                    name4 = f.cleaned_data['Name4'] or 'not set'
                    number4 = f.cleaned_data['Number4'] or 'not set'
                    relationship4 = f.cleaned_data['Relationship4'] or 'not set'
                    print(number4)

                    name5 = f.cleaned_data['Name5'] or 'not set'
                    number5 = f.cleaned_data['Number5'] or 'not set'
                    relationship5 = f.cleaned_data['Relationship5'] or 'not set'

                    try:
                        emergency_contact_response = requests.post("https://kayxrpz2ef.execute-api.us-west-2.amazonaws.com/production/data", json.dumps({ "httpMethod": 'POST', "AccessToken": auth['AccessToken'], "emergencyContacts": {"name":name, "name2":name2, "name3":name3,"name4":name4, "name5":name5,
                         "number":number, "number2":number2, "number3":number3,"number4":number4, "number5":number5,
                         "relationship":relationship, "relationship2":relationship2, "relationship3":relationship3, "relationship4":relationship4, "relationship5":relationship5}}), headers = {"Authorization": auth["token"]})
                    except Exception as e:
                        print(e)
                        return render( request, 'frontend/user_page.html', {'message': ERROR_OBTAIN_EMERGENCY_SEND})
                    emergency_contact_response = emergency_contact_response.json()
                    print("I am working")

                    if 'status' in emergency_contact_response and emergency_contact_response['status'] == 'Success':
                        return render(request, 'frontend/user_page.html', {'message': 'contact saved',
                        'email': email,
                        'name': name,
                        'name2': name2,
                        'name3': name3,
                        'name4': name4,
                        'name5': name5,
                        'number': number,
                        'number2': number2,
                        'number3': number3,
                        'number4': number4,
                        'number5': number5,
                        'relationship':relationship,
                        'relationship2':relationship2,
                        'relationship3':relationship3,
                        'relationship4':relationship4,
                        'relationship5':relationship5
                        })
                    print(emergency_contact_response);
                    return render(request, 'frontend/user_page.html', {'message': emergency_contact_response['msg']})
                else:
                    return render(request, 'frontend/user_page.html', {'message': ERROR_FILL_OUT})
            if user_analytics_response['status'] == 'Success':
                analytics = user_analytics_response['situp']
                if analytics == "not set":
                    return render(request, 'frontend/user_page.html', {'analytics_message': "No Analytics. Make sure the device is connected"})
                else:
                    return render(request, 'frontend/user_page.html', {'user_analytcs': analytics})
        else: #gets a new token using the refreshToken
            try:
                refresh_token_response = requests.get("https://bqseq2czwe.execute-api.us-west-2.amazonaws.com/prod/credential",  params = { "process": 'get_new_token', "RefreshToken": auth["RefreshToken"]})
            except Exception as e:
                print("shouldn't be here")
                fail_page = HttpResponseRedirect(reverse('login'))
                fail_page.delete_cookie("auth")
                try:
                    delete = requests.post("https://bqseq2czwe.execute-api.us-west-2.amazonaws.com/prod/credential",json.dumps({ "process":'logout',"email":auth["email"]}))
                except Exception as e:
                    print(e)
                return fail_page
            refresh_token_response = json.loads(refresh_token_response.content)
            if 'status' in refresh_token_response and refresh_token_response['status'] == 'Success':
                next = HttpResponseRedirect(reverse('user_page'))
                token_data = {"token": refresh_token_response['id_token'], "email": auth['email'], 'RefreshToken': auth["RefreshToken"], 'AccessToken': refresh_token_response['AccessToken']}
                next.set_cookie('auth', token_data)
                return next
            else:
                print("shouldn't be here")
                fail_page = HttpResponseRedirect(reverse('login'))
                fail_page.delete_cookie("auth")
                try:
                    delete = requests.post("https://bqseq2czwe.execute-api.us-west-2.amazonaws.com/prod/credential",json.dumps({ "process":'logout',"email":auth["email"]}))
                except Exception as e:
                    print(e)
                return fail_page
    else:
        return HttpResponseRedirect(reverse('index'))


def login(request):
    auth = request.COOKIES.get('auth')
    if auth:
        return HttpResponseRedirect(reverse('user_page'))
    if request.method == 'GET':
        request.session['errorMessage'] = ' '
        request.session['cred'] = "login"
        return HttpResponseRedirect(reverse('index'))
    f = LoginForm(request.POST)
    if f.is_valid():
        email = f.cleaned_data['email']
        password = f.cleaned_data['password']
        try:
            user_response = requests.post("https://bqseq2czwe.execute-api.us-west-2.amazonaws.com/prod/credential", json.dumps({ "process": 'authenticate', "email": email,"password": password}))
            print(user_response)
        except Exception as e:
            request.session['errorMessage'] = e
            request.session['cred'] = 'login'
            return HttpResponseRedirect(reverse('index'))
        user_response = json.loads(user_response.content)
        if 'status' in user_response and user_response['status'] == 'Success':
            user_page = HttpResponseRedirect(reverse('user_page'))
            token_data = {'token': user_response['id_token'], 'email': email, 'RefreshToken': user_response['RefreshToken'], 'AccessToken': user_response['AccessToken']}
            try:
                del request.session['errorMessage']
                del request.session['cred']
            except Exception as e:
                pass
            user_page.set_cookie('auth', token_data)
            return user_page
        else:
            request.session['errorMessage'] = user_response['error']
            request.session['cred'] = 'login'
            return HttpResponseRedirect(reverse('index'))
    else:
        request.session['errorMessage'] = 'email or Password is wrong'
        request.session['cred'] = 'logn'
        return HttpResponseRedirect(reverse('index'))




def register(request):
    auth = request.COOKIES.get('auth')
    #TODO make changes to the homepage tab so that I dont have to use this
    if auth:
        return HttpResponseRedirect(reverse('user_page'))
    if request.method == 'GET':
        request.session['errorMessage'] = ' '
        request.session['cred'] = "signup"
        return HttpResponseRedirect(reverse('index'))
    f = RegisterForm(request.POST)
    if f.is_valid():
        print("I am here in the valid form")
        email = f.cleaned_data['email']
        password = f.cleaned_data['password']
        name = f.cleaned_data['name']
        device_id = f.cleaned_data['device_id']
        try:
            device_reponse = requests.get("https://3ona7cpntd.execute-api.us-west-2.amazonaws.com/prod/devdata", params = {"process": "device_exist", "DevID":device_id})
        except Exception as e:
            request.session['errorMessage'] = e
            request.session['cred'] = 'signup'
            return HttpResponseRedirect(reverse('index'))
        device_reponse = device_reponse.json()
        if 'status' in device_reponse and device_reponse['status'] == 'Success':
            print("working valid form")
            print(device_reponse)
            #ip_address = device_reponse['IP']
        #TODO use a cookie to get the data instead of getters and setters
        #Checkout singleton
        #TODO check out a different ways to store cookie
            '''user_page = HttpResponseRedirect(reverse('user_page'))
            token_data = {'token': user_response['id_token'], 'email': email, 'RefreshToken': user_response['RefreshToken'], 'AccessToken': user_response['AccessToken']}
            user_page.set_cookie('auth', token_data)
            p.address = ip_address'''
            #request.session['ip_address'] = ip_address
        #TODO put this inside a try and catch block
        #TODO different variable names
            try:
                register_response=requests.post("https://bqseq2czwe.execute-api.us-west-2.amazonaws.com/prod/credential",json.dumps({"process": "register","email": email, "password":password , "name":name, "DevID":device_id}))
                request.session['cred'] = 'signup'
            except Exception as e:
                request.session['errorMessage'] = e
                request.session['cred'] = 'signup'
                return HttpResponseRedirect(reverse('index'))
            register_response = json.loads(register_response.content)
            if 'status' in register_response and register_response['status'] == 'Success':
                print("registered")
                request.session['errorMessage'] = "verify your email"
                return HttpResponseRedirect(reverse('index'))
            elif 'status' in register_response and 'msg' in register_response and register_response['msg'] == ERROR_USEREXISTS:
                request.session['errorMessage'] = ERROR_USEREXISTS + ' with the same email'
                return HttpResponseRedirect(reverse('index'))
            else:
                request.session['errorMessage'] = ERROR_SIGNUP
                return HttpResponseRedirect(reverse('index'))
        else:
            request.session['errorMessage'] = ERROR_DEVICE
            request.session['cred'] = 'signup'
            return HttpResponseRedirect(reverse('index'))
    else:
        request.session['errorMessage'] = 'Input was not of correct form'
        request.session['cred'] = 'signup'
        return HttpResponseRedirect(reverse('index'))

def logout(request):
    auth = request.COOKIES.get('auth')
    print(auth)
    #TODO keep everything to positive
    if auth:
        login_page = HttpResponseRedirect(reverse('login'))
        login_page.delete_cookie("auth")
        auth = auth.replace("'", '"')
        auth = json.loads(auth)
        email = auth["email"]
        try:
            delete = requests.post("https://bqseq2czwe.execute-api.us-west-2.amazonaws.com/prod/credential",json.dumps({ "process":'logout',"email":email}))
        except Exception as e:
            print(e)
        return login_page
    else:
        return HttpResponseRedirect(reverse('index'))

def forgot_password(request):
    auth = request.COOKIES.get('auth')
    if request.method == 'GET':
        request.session['errorMessage'] = ' '
        request.session['cred'] = "forgot-password"
        return HttpResponseRedirect(reverse('index'))
    f = forgotPasswordForm(request.POST)
    if f.is_valid():
        email = f.cleaned_data['email']
        print(email)
        #TODO try and catch
        try:
            forgot_password_response=requests.post("https://bqseq2czwe.execute-api.us-west-2.amazonaws.com/prod/credential",json.dumps({"process": "forgot_password", "email":email}))
            request.session['cred'] = "forgot-password"
        except Exception as e:
            request.session['errorMessage'] = ERROR_SIGNUP
            request.session['cred'] = "forgot-password"
            return HttpResponseRedirect(reverse('index'))
        forgot_password_response = json.loads(forgot_password_response.content)
        if 'status' in forgot_password_response and forgot_password_response['status'] == 'Success':
            request.session['errorMessage'] = "check your email for the confirmation code"
            request.session['cred'] = "reset_password"
            return HttpResponseRedirect(reverse('index'))
        else:
            request.session['errorMessage'] = ERROR_SIGNUP
            return HttpResponseRedirect(reverse('index'))
    else:
        request.session['errorMessage'] = "Make sure the email is correct"
        request.session['cred'] = "forgot-password"
        return HttpResponseRedirect(reverse('index'))

def reset_password(request):
    auth = request.COOKIES.get('auth')
    if request.method == 'GET':
        request.session['errorMessage'] = ''
        request.session['cred'] = "reset_password"
        return HttpResponseRedirect(reverse('index'))
    f = resetPasswordForm(request.POST)
    if f.is_valid():
        email = f.cleaned_data['email']
        confirmationCode = f.cleaned_data['confirmationCode']
        newPassword = f.cleaned_data['newPassword']
        try:
            reset_password_response=requests.post("https://bqseq2czwe.execute-api.us-west-2.amazonaws.com/prod/credential",json.dumps({"process": "confirm_forgot_password", "confirmationCode":confirmationCode, "newPassword": newPassword, "email":email}))
            request.session['cred'] = "reset_password"
        except Exception as e:
            request.session['errorMessage'] = ERROR_SIGNUP
            request.session['cred'] = "reset_password"
            return HttpResponseRedirect(reverse('index'))
            return render(request, 'frontend/reset_password.html', {'errorMessage': e, 'form': reset_password_form})
        reset_password_response = json.loads(reset_password_response.content)
        if 'status' in reset_password_response and reset_password_response['status'] == 'Success':
            request.session['errorMessage'] = 'successfully changed!'
            return HttpResponseRedirect(reverse('index'))
        else:
            print("i have failed")
            request.session['errorMessage'] = ERROR_SIGNUP
            return HttpResponseRedirect(reverse('index'))
    else:
        request.session['errorMessage'] = ERROR_FILL_OUT
        request.session['cred'] = "reset_password"
        return HttpResponseRedirect(reverse('index'))
