from django.shortcuts import render
from django import forms
from django.http import HttpResponse
from django.http import JsonResponse
# from django.contrib.auth import logout
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

# from views import errorMsg
#Static variables for error outputs
ERROR_FILL_OUT = "Please fill out all fields"
ERROR_OBTAIN_DATA = "Coudln't obtain your data. Please contact"
ERROR_OBTAIN_EMERGENCY_SEND = "Coudln't send the emergency data"
ERROR_TOKEN_SEND = "Coudn't send tokens please contact us"
ERROR_SIGNUP = "Invalid Username or Password"
ERROR_DEVICE = "DeviceID not found"
ERROR_USEREXISTS = "user already exists"
