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

#Static variables for error outputs
ERROR_FILL_OUT = "Please fill out all fields"
ERROR_OBTAIN_DATA = "Coudln't obtain your data. Please contact"
ERROR_OBTAIN_EMERGENCY_SEND = "Coudln't send the emergency data"
ERROR_TOKEN_SEND = "Coudn't send tokens please contact us"
ERROR_SIGNUP = "Invalid email or Password"
ERROR_DEVICE = "DeviceID not found"
ERROR_USEREXISTS = "user already exists"

# Routing to the main page of the website
def index(request):
    auth = request.COOKIES.get('auth')
    try:
        errorMessage = request.session['errorMessage']
        cred = request.session['cred']
        print(cred)
    except Exception as e:
        errorMessage = None
        cred = None
    #errormessage -> may be causing infinite loop
    if errorMessage != None:
        print(errorMessage)
        del request.session['errorMessage']
        del request.session['cred']
        print(cred)
        return render(request, 'frontend/index.html', {'auth': auth, 'errorMessage': errorMessage, 'cred': cred})
    return render(request, 'frontend/index.html', {'auth': auth, 'errorMessage': None})

#verification page
def verify(request):
    auth = request.COOKIES.get('auth')
    return render(request, 'frontend/verify.html')

#verification page
def faq(request):
    auth = request.COOKIES.get('auth')
    return render(request, 'frontend/faq.html')

#Routing to the userpage
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
    #if there is error go back to the index.html page
    if errorMessage != None:
        print(errorMessage)
        del request.session['errorMessage']
        del request.session['cred']
        print(cred)
        return render(request, 'frontend/index.html', {'auth': auth, 'errorMessage': errorMessage, 'cred': cred})
    if auth:
        auth = auth.replace("'", '"')
        auth = json.loads(auth)
        print("this is the auth: {}".format(auth))
        usersname = auth["usersname"]
        try:
            print("it is working 2")
            #obtainning back the user emergency contact infos
            user_data_response = requests.get("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user-data", params = {"AccessToken": auth['AccessToken']}, headers = {"Authorization": auth["token"]})
            print(user_data_response)
        except Exception as e:
            return render( request, 'frontend/user_page.html', {'message': ERROR_OBTAIN_DATA})
        try:
            #obtainning back the graph/situps/sitdown etc data
            User_Analytics = requests.get("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/device-user-data", params = {"AccessToken": auth['AccessToken'], "position":"situp"} , headers = {"Authorization": auth["token"]})
        except Exception as e:
            return render( request, 'frontend/user_page.html', {'message': ERROR_OBTAIN_DATA})
        print(User_Analytics.content)
        user_data_response = json.loads(user_data_response.content)
        user_analytics_response = json.loads(User_Analytics.content)
        print("after user_anaylytsc response")
        print(user_analytics_response)
        print(user_data_response)
        #only load the page if the queries do not have any errors.
        if 'status' in user_data_response and 'status' in user_analytics_response:
            #I need to be more robust about the failed cases, but for not go as it is.
            if user_data_response['status'] == 'Success' and user_analytics_response['status'] == 'Success':
                print("inside the success")
                analytics = user_analytics_response['userData']
                print(analytics)
                if analytics and analytics is not 'not set' and analytics != "situp" and analytics != "fall":
                    userAnalytics = analytics.split(' , ')
                    print(userAnalytics[1:])
                    userDataList = {}
                    for i in userAnalytics[1:]:
                        userDatas = i.split(' ')
                        if userDatas[0] in userDataList:
                            userDataList[userDatas[0]].append(userDatas[1])
                        else:
                            userDataList[userDatas[0]] = [userDatas[1]]
                            print(userDataList)
                content = user_data_response['emergency_contacts']
                print(content)
                if request.method == 'GET':
                    #check if the emergency datas are set from the user or not
                    if content == "not set":
                        return render(request, 'frontend/user_page.html', {'usersname': usersname, 'message': content, 'user_analytcs': analytics})
                    else:
                        #make the field here dynamic
                        """for key, value in content.items():
                            if value == "not set":
                                content[key] = 'not set'
"""
                        return render(request, 'frontend/user_page.html', {'message': 'contact saved',
                        'usersname': usersname,
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
                        'relationship5':content['relationship5'],
                        'user_analytcs': analytics
                        })
                f = emergencyContactForm(request.POST)
                print(f.is_valid())
                print(f)
                print("I contactform")
                #if new emergency contact is formed go here
                if f.is_valid() and request.method != 'GET':
                    print("form is valid")
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
                        emergency_contact_response = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user-data", json.dumps({ "httpMethod": 'POST', "AccessToken": auth['AccessToken'], "emergencyContacts": {"name":name, "name2":name2, "name3":name3,"name4":name4, "name5":name5,
                         "number":number, "number2":number2, "number3":number3,"number4":number4, "number5":number5,
                         "relationship":relationship, "relationship2":relationship2, "relationship3":relationship3, "relationship4":relationship4, "relationship5":relationship5}}), headers = {"Authorization": auth["token"]})
                    except Exception as e:
                        print(e)
                        return render( request, 'frontend/user_page.html', {'message': ERROR_OBTAIN_EMERGENCY_SEND})
                    emergency_contact_response = emergency_contact_response.json()
                    print("I am working")

                    if 'status' in emergency_contact_response and emergency_contact_response['status'] == 'Success':
                        return render(request, 'frontend/user_page.html', {'message': 'contact saved',
                        'usersname':usersname,
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
                        'relationship5':relationship5,
                        'user_analytcs': analytics
                        })
                    print(emergency_contact_response);
                    return render(request, 'frontend/user_page.html', {'message': emergency_contact_response['errorMessage']})
                else:
                    return render(request, 'frontend/user_page.html', {'message': ERROR_FILL_OUT})
        else: #gets a new token using the refreshToken
            try:
                refresh_token_response = requests.get("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/credential",  params = { "process": 'get_new_token', "RefreshToken": auth["RefreshToken"]})
            except Exception as e:
                print("shouldn't be here")
                #failed to obtain the refreshtoken -> go back to login
                fail_page = HttpResponseRedirect(reverse('login'))
                fail_page.delete_cookie("auth")
                try:
                    delete = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/credential",json.dumps({ "process":'logout',"email":auth["email"]}))
                except Exception as e:
                    print(e)
                return fail_page
            refresh_token_response = json.loads(refresh_token_response.content)
            if 'status' in refresh_token_response and refresh_token_response['status'] == 'Success':
                next = HttpResponseRedirect(reverse('user_page'))
                token_data = {"token": refresh_token_response['id_token'], 'RefreshToken': auth["RefreshToken"], 'AccessToken': refresh_token_response['AccessToken']}
                next.set_cookie('auth', token_data)
                return next
            else:
                #the token itself is bad go back to login
                print("shouldn't be here")
                fail_page = HttpResponseRedirect(reverse('login'))
                fail_page.delete_cookie("auth")
                try:
                    delete = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/credential",json.dumps({ "process":'logout',"email":auth["email"]}))
                except Exception as e:
                    print(e)
                return fail_page
    else:
        return HttpResponseRedirect(reverse('index'))

def login(request):
    auth = request.COOKIES.get('auth')
    #if you already logged in and have auth token
    if auth:
        return HttpResponseRedirect(reverse('user_page'))
    #if you are requesting for the login page
    request.session['cred'] = "login"
    if request.method == 'GET':
        request.session['errorMessage'] = ' '
        return HttpResponseRedirect(reverse('index'))
    f = LoginForm(request.POST)
    if f.is_valid():
        username = f.cleaned_data['username']
        password = f.cleaned_data['password']
        try:
            user_response = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/credential", json.dumps({ "process": 'authenticate', "username": username,"password": password}))
        except Exception as e:
            request.session['errorMessage'] = e
            return HttpResponseRedirect(reverse('index'))
        user_response = json.loads(user_response.content)
        if 'status' in user_response and user_response['status'] == 'Success':
            user_page = HttpResponseRedirect(reverse('user_page'))
            print("name: {}".format(user_response['username']))
            token_data = {'token': user_response['id_token'], 'usersname':user_response['username'], 'RefreshToken': user_response['RefreshToken'], 'AccessToken': user_response['AccessToken']}
            try:
                del request.session['errorMessage']
                del request.session['cred']
            except Exception as e:
                pass
            user_page.set_cookie('auth', token_data)
            return user_page
        else:
            print("this is user_response: {}".format(user_response))
            if 'User does not exist' in user_response['errorMessage']:
                request.session['errorMessage'] = 'User does not exist'
            elif 'Incorrect username or password' in user_response['errorMessage']:
                request.session['errorMessage'] = 'Incorrect username or password'
            else:
                request.session['errorMessage'] = user_response['errorMessage']
            return HttpResponseRedirect(reverse('index'))
    else:
        request.session['errorMessage'] = 'email or Password is wrong'
        return HttpResponseRedirect(reverse('index'))




def register(request):
    auth = request.COOKIES.get('auth')
    #TODO make changes to the homepage tab so that I dont have to use this
    if auth:
        return HttpResponseRedirect(reverse('user_page'))
    request.session['cred'] = "signup"
    if request.method == 'GET':
        request.session['errorMessage'] = ' '
        return HttpResponseRedirect(reverse('index'))
    f = RegisterForm(request.POST)
    if f.is_valid():
        print("I am here in the valid form")
        email = f.cleaned_data['email']
        password = f.cleaned_data['password']
        username = f.cleaned_data['username']
        confirm_password = f.cleaned_data['confirm_password']
        if password != confirm_password:
            request.session['errorMessage'] = "passwords did not match"
            return HttpResponseRedirect(reverse('index'))
        #code for adding device ID
        """device_id = f.cleaned_data['device_id']
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
            #ip_address = device_reponse['IP']"""
        try:
            register_response=requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/credential",json.dumps({"process": "register","email": email, "password":password , "username":username}))
        except Exception as e:
            request.session['errorMessage'] = e
            return HttpResponseRedirect(reverse('index'))
        register_response = json.loads(register_response.content)
        if 'status' in register_response and register_response['status'] == 'Success':
            print("registered")
            request.session['errorMessage'] = "verify your email"
        elif 'status' in register_response and 'msg' in register_response and register_response['msg'] == ERROR_USEREXISTS:
            request.session['errorMessage'] = ERROR_USEREXISTS + ' with the same email'
        else:
            request.session['errorMessage'] = ERROR_SIGNUP

    #"""    else:
    #        request.session['errorMessage'] = ERROR_DEVICE
    #        request.session['cred'] = 'signup'
    #        return HttpResponseRedirect(reverse('index'))"""
    else:
        request.session['errorMessage'] = 'Input was not of correct form'
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
        print(auth)
        try:
            username = auth["username"]
        except:
            return login_page
        try:
            delete = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/credential",json.dumps({ "process":'logout',"username":username}))
        except Exception as e:
            print(e)
        return login_page
    else:
        return HttpResponseRedirect(reverse('index'))

def forgot_password(request):
    auth = request.COOKIES.get('auth')
    request.session['cred'] = "forgot-password"
    if request.method == 'GET':
        request.session['errorMessage'] = ' '
        return HttpResponseRedirect(reverse('index'))
    f = forgotPasswordForm(request.POST)
    if f.is_valid():
        email = f.cleaned_data['email']
        print("inside the forgot password")
        print(email)
        #TODO try and catch
        try:
            forgot_password_response=requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/credential",json.dumps({"process": "forgot_password", "email":email}))
        except Exception as e:
            request.session['errorMessage'] = ERROR_SIGNUP
            return HttpResponseRedirect(reverse('index'))
        forgot_password_response = json.loads(forgot_password_response.content)
        if 'status' in forgot_password_response and forgot_password_response['status'] == 'Success':
            print("success in getting the right response")
            request.session['errorMessage'] = "check your email for the confirmation code"
            request.session['cred'] = "reset_password"
        else:
            request.session['errorMessage'] = ERROR_SIGNUP
    else:
        request.session['errorMessage'] = "Make sure the email is correct"
    return HttpResponseRedirect(reverse('index'))

def reset_password(request):
    auth = request.COOKIES.get('auth')
    request.session['cred'] = "reset_password"
    if request.method == 'GET':
        request.session['errorMessage'] = 'not set'
        return HttpResponseRedirect(reverse('index'))
    f = resetPasswordForm(request.POST)
    if f.is_valid():
        email = f.cleaned_data['email']
        confirmationCode = f.cleaned_data['confirmationCode']
        newPassword = f.cleaned_data['newPassword']
        try:
            reset_password_response=requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/credential",json.dumps({"process": "confirm_forgot_password", "confirmationCode":confirmationCode, "newPassword": newPassword, "email":email}))
        except Exception as e:
            request.session['errorMessage'] = ERROR_SIGNUP
            return HttpResponseRedirect(reverse('index'))
        reset_password_response = json.loads(reset_password_response.content)
        if 'status' in reset_password_response and reset_password_response['status'] == 'Success':
            request.session['errorMessage'] = 'successfully changed!'
        else:
            print("i have failed")
            request.session['errorMessage'] = ERROR_SIGNUP
    else:
        request.session['errorMessage'] = ERROR_FILL_OUT
    return HttpResponseRedirect(reverse('index'))
