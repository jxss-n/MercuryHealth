from .imports import *

def accept_payment(req) :
    return render(req, 'frontend/accept_payment.html', {})

def payment_success(req):
    return render(req, 'frontend/payment_success.html', {})
