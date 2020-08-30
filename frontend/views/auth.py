from .imports import *

def login(request):
    auth = request.COOKIES.get('auth')
    #if you already logged in and have auth token
    if auth and auth.find("usersname") != -1:
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
            user_response = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/credential", json.dumps({ "process": 'authenticate', "username": username,"password": password}))
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
        request.session['errorMessage'] = 'Username or Password is wrong'
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
        #email = f.cleaned_data['email']
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
            register_response=requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/credential",json.dumps({"process": "register", "password":password , "username":username}))
        except Exception as e:
            request.session['errorMessage'] = e
            return HttpResponseRedirect(reverse('index'))
        register_response = json.loads(register_response.content)
        if 'status' in register_response and register_response['status'] == 'Success':
            print("registered")
            request.session['errorMessage'] = "Please wait couple days for your account be to approved"
        elif 'status' in register_response and 'msg' in register_response and register_response['msg'] == ERROR_USEREXISTS:
            request.session['errorMessage'] = ERROR_USEREXISTS + ' with the same username'
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
    # print(auth)
    
    if auth:
        login_page = HttpResponseRedirect(reverse('login'))
        login_page.delete_cookie("auth")
        auth = auth.replace("'", '"')
        auth = json.loads(auth)
        # print(auth)

        try:
            username = auth["username"]
        except:
            return login_page
        try:
            delete = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/credential",json.dumps({ "process":'logout',"username":username}))
        except Exception as e:
            print(e)
        return login_page
    else:
        return HttpResponseRedirect(reverse('index'))
