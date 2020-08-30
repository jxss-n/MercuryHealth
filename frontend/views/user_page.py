from .imports import *

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
        # print("this is the auth: {}".format(auth))
        usersname = auth["usersname"]
        try:
            #obtainning back the user emergency contact infos
            user_data_response = requests.get("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/data", params = {"AccessToken": auth['AccessToken']}, headers = {"Authorization": auth["token"]})
            # print(user_data_response)
        except Exception as e:
            return render( request, 'frontend/user_page.html', {'message': ERROR_OBTAIN_DATA})
        try:
            #obtainning back the graph/situps/sitdown etc data
            User_Analytics = requests.get("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/device/analytics", params = {"AccessToken": auth['AccessToken'], "position":"situp"} , headers = {"Authorization": auth["token"]})
        except Exception as e:
            return render( request, 'frontend/user_page.html', {'message': ERROR_OBTAIN_DATA})
        # print(User_Analytics.content)
        user_data_response = json.loads(user_data_response.content)
        user_analytics_response = json.loads(User_Analytics.content)
        # print("after user_anaylytsc response")
        # print(user_analytics_response)
        # print(user_data_response)
        #only load the page if the queries do not have any errors.
        if 'status' in user_data_response and 'status' in user_analytics_response:
            #I need to be more robust about the failed cases, but for not go as it is.
            if user_data_response['status'] == 'Success' and user_analytics_response['status'] == 'Success':
                print("inside the success")
                analytics = user_analytics_response['userData']
                # print(analytics)
                if analytics and analytics != 'not set' and analytics != "situp" and analytics != "fall":
                    userAnalytics = analytics
                    # print(userAnalytics)
                    userDataList = {}
                    for i in userAnalytics:
                        userDatas = i.split(' ')
                        if userDatas[0] in userDataList:
                            userDataList[userDatas[0]].append(userDatas[1])
                        else:
                            userDataList[userDatas[0]] = [userDatas[1]]
                            # print(userDataList)
                analytics = ' , '.join(analytics)
                # print("[views.py line 171] {}".format(analytics))
                content = user_data_response['emergency_contacts']
                # print("[views.py line 173] {}".format(content))
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
                        'name': content['contact1']['name'],
                        'name2': content['contact2']['name'],
                        'name3': content['contact3']['name'],
                        'name4': content['contact4']['name'],
                        'name5': content['contact5']['name'],
                        'number': content['contact1']['number'],
                        'number2': content['contact2']['number'],
                        'number3': content['contact3']['number'],
                        'number4': content['contact4']['number'],
                        'number5': content['contact5']['number'],
                        'relationship':content['contact1']['relationship'],
                        'relationship2':content['contact2']['relationship'],
                        'relationship3':content['contact3']['relationship'],
                        'relationship4':content['contact4']['relationship'],
                        'relationship5':content['contact5']['relationship'],
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
                        emergency_json = { "httpMethod": 'POST',
                        "AccessToken": auth['AccessToken'],
                        "emergencyContacts": {"contact1":{"name":name, "number":number, "relationship":relationship},
                        "contact2":{"name":name2, "number":number2, "relationship":relationship2},
                        "contact3":{"name":name3, "number":number3, "relationship":relationship3},
                        "contact4":{"name":name4, "number":number4, "relationship":relationship4},
                        "contact5":{"name":name5, "number":number5, "relationship":relationship5}}}
                        emergency_contact_response = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/data", json.dumps(emergency_json), headers = {"Authorization": auth["token"]})
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
                refresh_token_response = requests.get("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/credential",  params = { "process": 'get_new_token', "RefreshToken": auth["RefreshToken"]})
            except Exception as e:
                print("shouldn't be here")
                #failed to obtain the refreshtoken -> go back to login
                fail_page = HttpResponseRedirect(reverse('login'))
                fail_page.delete_cookie("auth")
                try:
                    delete = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/credential",json.dumps({ "process":'logout',"username":auth["usersname"]}))
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
                    delete = requests.post("https://wzxac2vv46.execute-api.us-west-2.amazonaws.com/mercury-health/user/credential",json.dumps({ "process":'logout',"username":auth["usersname"]}))
                except Exception as e:
                    print(e)
                return fail_page
    else:
        return HttpResponseRedirect(reverse('index'))
