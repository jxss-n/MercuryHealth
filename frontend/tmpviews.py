



#verification page
def verify(request):
    auth = request.COOKIES.get('auth')
    return render(request, 'frontend/verify.html')
