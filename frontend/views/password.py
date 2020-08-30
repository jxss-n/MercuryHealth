from .imports import *

def forgot_password(request):
    auth = request.COOKIES.get('auth')
    request.session['cred'] = "forgot-password"
    if request.method == 'GET':
        request.session['errorMessage'] = ' '
        return HttpResponseRedirect(reverse('index'))
    request.session['errorMessage'] = "Please contact contact@mercuryhealth.us to change your password"
    """f = forgotPasswordForm(request.POST)
    if f.is_valid():
        #email = f.cleaned_data['email']
        print("inside the forgot password")
        print(email)
        #TODO try and catch
        try:
            forgot_password_response=requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/credential",json.dumps({"process": "forgot_password", "email":email}))
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
    """
    return HttpResponseRedirect(reverse('index'))

def reset_password(request):
    auth = request.COOKIES.get('auth')
    request.session['cred'] = "reset_password"
    if request.method == 'GET':
        request.session['errorMessage'] = 'not set'
        return HttpResponseRedirect(reverse('index'))
    request.session['errorMessage'] = "Please contact contact@mercuryhealth.us to change your password"
    """f = resetPasswordForm(request.POST)
    if f.is_valid():
        email = f.cleaned_data['email']
        confirmationCode = f.cleaned_data['confirmationCode']
        newPassword = f.cleaned_data['newPassword']
        try:
            reset_password_response=requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/credential",json.dumps({"process": "confirm_forgot_password", "confirmationCode":confirmationCode, "newPassword": newPassword, "email":email}))
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
        request.session['errorMessage'] = ERROR_FILL_OUT"""
    return HttpResponseRedirect(reverse('index'))
