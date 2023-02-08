from contextlib import _RedirectStream
from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login, logout
from Login import settings
from django.core.mail import send_mail, EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str, force_bytes
from . tokens import generate_token



# Create your views here.
def home(request):
    return render(request,'authentication/base.html')

def signup(request):

    if request.method == 'POST':
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')

        if User.objects.filter(username=username):
            messages.error(request, "Username already exists!!")
            return redirect('signup')
            
        if User.objects.filter(email=email):
            messages.error(request,"Email already registered")
            return redirect('signup')

        if len(username) > 10:
            messages.error(request,"Username must be under 10 characters.")
            return redirect('signup')

        if pass1 != pass2:
            messages.error(request, "Password didn't match!!")
            return redirect('signup')

        if not username.isalnum():
            messages.error("Username must be alphanumeric!!")
            return redirect('signup')

        myuser = User.objects.create_user(username,email,pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        # myuser.is_active = False
        myuser.save()

        messages.success(request, "Your account has been successfully created. Please check your email for confirmation to activate your account.\n\nNote: you need to verify your email for activation.\n")
        
         #Welcome Email
        subject = "Welcome to abcd!!"
        message = "Hello " + myuser.first_name + "\n\n Thank you for visiting our website. Please confirm your email address in order to activate your account.\n\nThank You\n\nAnupama"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject,message,from_email, to_list, fail_silently=True)

        # #Email Address confirmation

        current_site = get_current_site(request)
        email_subject = "Confirm your email @ abcd - Django Login"
        message1 = render_to_string('email_confirmation.html',{
            'name':myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser),
        })

        email = EmailMessage(
            email_subject,
            message1,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )

        email.fail_silently = True

        email.send()


        return redirect('signin')
    return render(request,'authentication/signup.html')

def signin(request):

    if request.method == 'POST':
        un = request.POST.get('username')
        pw = request.POST.get('pass1')

        user = authenticate(username =  un, password = pw)

        if user is not None:
            login(request,user)
            fname = user.first_name
            return render(request,"authentication/index.html",{'fname': fname})

        else:
            messages.error(request, "Bad Credintials")
            return redirect('signin')
    return render(request,'authentication/signin.html')

def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully")
    return redirect('home')
    
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect('home')
    
    else:
        return render(request, "activation_failed.html")
    

