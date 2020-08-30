from .imports import *

# Routing to the main page of the website
def index(request):
    auth = request.COOKIES.get('auth')
    print("[views.py line 37] first auth type: {}".format(type(auth)))
    if auth:
        auth = auth.replace("'", '"')
        auth = json.loads(auth)
    else:
        auth = {}

    #return render(request, 'frontend/index.html', {'auth': None, 'errorMessage': None})
    try:
        usersname = auth['usersname']
    except KeyError:
        print("[views.py line 46] auth[usersname] doesnt exist")
        return render(request, 'frontend/index.html', {'auth': None, 'errorMessage': None})

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


# FAQ page
def faq(request):
    auth = request.COOKIES.get('auth')
    return render(request, 'frontend/faq.html', {'auth': auth, 'errorMessage': None})

# Beta page
def beta(request):
    auth = request.COOKIES.get('auth')
    if request.method == "GET":
        return render(request, 'frontend/beta.html', {'auth': auth, 'errorMessage': None})
    if request.COOKIES.get('beta_count') != None:
        print(request.COOKIES.get('beta_count'))
        count = int(request.COOKIES.get('beta_count'))
        if count == 5:
            return render(request, 'frontend/beta.html', {'auth': auth, 'errorMessage': 'You have registered too many times!'})
    params = dict(request.POST)
    del params['csrfmiddlewaretoken']
    print(params)
    params['process'] = 'register_beta_tester'
    for key in params.keys():
        params[key] = str(params[key])
    try:
        beta_response = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/register-beta",   json.dumps(dict(params)))
        print(beta_response.content)
    except Exception as e:
        print('ERROR')
        print(e)
        request.session['errorMessage'] = e
        return HttpResponseRedirect(reverse('beta'))
    beta_response = json.loads(beta_response.content)
    if 'status' in beta_response and beta_response['status'] == 'Success':
        beta = HttpResponseRedirect(reverse('beta'))
        if request.COOKIES.get('beta_count') != None:
            print(request.COOKIES.get('beta_count'))
            count = int(request.COOKIES.get('beta_count'))
            beta_data = str(count+1)
        else:
            beta_data = "1"
        beta.set_cookie('beta_count', beta_data)
        return beta
    return HttpResponseRedirect(reverse('beta'))
