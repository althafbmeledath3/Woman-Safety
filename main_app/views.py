def delete_account(request, username):
    try:
        user = User.objects.get(username=username)
        user.delete()
        messages.success(
            request, user.username + ", Your account is deleted successfully!"
        )
    except User.DoesNotExist:
        messages.error(request, "User doesnot exist")
    return redirect("main_app:home")
def login_request(request):
    form = LoginForm(request.POST)
    username = request.POST.get("Username_or_Email")
    password = request.POST.get("password")
    if request.method == "POST":
        # Allow sign in using just username/email and password (no CAPTCHA)
        if username and password:
            # Authenticate by username
            if User.objects.filter(username=username).exists():
                user = auth.authenticate(username=username, password=password)
                if user:
                    if user.is_active:
                        login(request, user)
                        messages.success(
                            request,
                            "Welcome, " + user.username + " you are now logged in",
                        )
                        return redirect("main_app:home")
                    else:
                        messages.error(request, "Account is not active, please check your email")
                else:
                    messages.error(request, "Invalid username or password")
            # Authenticate by email
            elif User.objects.filter(email=username).exists():
                user_obj = User.objects.get(email=username)
                user = auth.authenticate(username=user_obj.username, password=password)
                if user:
                    if user.is_active:
                        login(request, user)
                        messages.success(
                            request,
                            "Welcome, " + user.username + " you are now logged in",
                        )
                        return redirect("main_app:home")
                    else:
                        messages.error(request, "Account is not active, please check your email")
                else:
                    messages.error(request, "Invalid username or password")
            else:
                messages.error(request, "Invalid username or password")
                return redirect("main_app:login")
        else:
            messages.error(request, "Please enter username/email and password")
    form = LoginForm()
    return render(request, "main_app/login.html", {"form": form})
def logout_request(request):
    logout(request)
    messages.info(request, "Logged out successfully!")
    return redirect("main_app:home")
from django.shortcuts import render, redirect
from django.contrib.auth.forms import (
    PasswordChangeForm,
)
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib import messages
from .forms import ContactForm
from django.conf import settings
from .models import contact
from django.contrib.auth.models import User, auth
from .mail import send_email
from .whatsapp import send_whatsapp
from .location import lat, log
from .forms import UserCreateForm, LoginForm
from django.core.mail import EmailMessage
from django.views import View
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import account_activation_token
from django.http import JsonResponse
import json
import urllib

# Create your views here


def home(request):
    context = {}
    return render(request, "main_app/home.html", context)


def register(request):
    if request.method == "POST":
        form = UserCreateForm(request.POST)
        username = request.POST.get("username")
        email = request.POST.get("email")
        password1 = request.POST.get("password1")  # noqa
        password2 = request.POST.get("password2")  # noqa
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get("username")
            email = form.cleaned_data.get("email")
            user.is_active = False
            user.save()

            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            domain = get_current_site(request).domain
            link = reverse(
                "activate",
                kwargs={
                    "uidb64": uidb64,
                    "token": account_activation_token.make_token(user),
                },
            )

            activate_url = "http://" + domain + link

            email_subject = "Rescue - Activate you Account!"
            email_body = (
                "Hi  "
                + user.username  # noqa
                + "  ,  Please use this link to verify your account\n"  # noqa
                + activate_url  # noqa
            )
            email = EmailMessage(
                email_subject,
                email_body,
                "noreply@gmail.com",
                [email],
            )
            messages.success(request, f"New Account Created Successfully: {username}")
            messages.success(request, "Check your email to Activate your account!")
            email.send(fail_silently=False)
            return redirect('main_app:email_sent')
        elif User.objects.filter(username=username).exists():
            messages.warning(
                request,
                "The username you entered has already been taken. Please try another username",
            )
        elif User.objects.filter(email=email).exists():
            messages.warning(
                request,
                "The Email you entered has already been taken. Please try another Email",
            )
        else:
            for msg in form.error_messages:
                messages.warning(request, f"{form.error_messages[msg]}")

    else:
        form = UserCreateForm()
    return render(request, "main_app/register.html", {"form": form})


class VerificationView(View):
    def get(self, request, uidb64, token):
        try:
            id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=id)

            if not account_activation_token.check_token(user, token):
                return redirect(
                    "main_app:login" + "?message=" + "User already activated"
                )

            if user.is_active:
                return redirect("main_app:login")
            user.is_active = True
            user.save()

            messages.success(request, "Account activated successfully")
            return redirect("main_app:login")

        except Exception:
            pass

        return redirect("main_app:login")


from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def emergency(request):
    if not request.user.is_authenticated:
        return redirect("main_app:login")
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode())
            lat = data.get("lat")
            lng = data.get("lng")
            if not lat or not lng:
                return JsonResponse({"success": False, "error": "Location not provided"})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})

        contacts = contact.objects.filter(user=request.user)
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        subject = "EMERGENCY: I am in danger!"
        location_link = f"http://www.google.com/maps/place/{lat},{lng}"
        body = f"I am in danger, please help me! My location: {location_link}"

        EMAIL_HOST = 'smtp.gmail.com'
        EMAIL_HOST_USER = 'mariyaann894@gmail.com'
        EMAIL_HOST_PASSWORD = 'auru ctjv zfqo shni'
        EMAIL_PORT = 587

        all_sent = True
        for c in contacts:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_HOST_USER
            msg['To'] = c.email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            try:
                server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
                server.starttls()
                server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
                server.sendmail(EMAIL_HOST_USER, c.email, msg.as_string())
                server.quit()
            except Exception as e:
                all_sent = False
        return JsonResponse({"success": all_sent})
    else:
        return render(request, "main_app/emergency.html")
    


def update_contact(request, pk):
    curr_contact = contact.objects.get(id=pk)
    name = curr_contact.name
    form = ContactForm(
        initial={
            "name": name,
            "email": curr_contact.email,
            "mobile_no": curr_contact.mobile_no,
            "relation": curr_contact.relation,
        }
    )
    if request.method == "POST":
        form = ContactForm(request.POST, instance=curr_contact)
        if form.is_valid():
            form.save()
            messages.error(request, f"{name} updated successfully!!")
            messages.info(request, "A message has been sent to your contact!!")
            return redirect("main_app:emergency_contact")
    context = {"form": form}
    return render(request, "main_app/create_contact.html", context)


def delete_contact(request, pk):
    curr_contact = contact.objects.get(id=pk)
    name = curr_contact.name
    if request.method == "POST":
        curr_contact.delete()
        messages.error(request, f"{name} deleted successfully!!")
        return redirect("main_app:emergency_contact")
    context = {"item": curr_contact}
    return render(request, "main_app/delete_contact.html", context)


def emergency_contact(request):
    if not request.user.is_authenticated:
        return redirect("main_app:login")
    contacts = contact.objects.filter(user=request.user)
    return render(request, "main_app/emergency_contact.html", {
        "contacts": contacts,
        "total_contacts": contacts.count(),
        "user": request.user,
    })


def create_contact(request):
    if not request.user.is_authenticated:
        return redirect("main_app:login")
    if request.method == "POST":
        form = ContactForm(request.POST)
        if form.is_valid():
            contact_obj = form.save(commit=False)
            contact_obj.user = request.user
            contact_obj.save()
            messages.success(request, f"Contact {contact_obj.name} created successfully!")
            return redirect("main_app:emergency_contact")
    else:
        form = ContactForm()
    return render(request, "main_app/create_contact.html", {"form": form})


def change_password(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, "Your password was successfully updated!")
            return redirect("main_app:home")
        else:
            for msg in form.error_messages:
                messages.error(request, f"{form.error_messages[msg]}")
    else:
        form = PasswordChangeForm(request.user)
    return render(request, "main_app/change_password.html", {"form": form})


def helpline_numbers(request):
    return render(
        request, "main_app/helpline_numbers.html", {"title": "helpline_numbers"}
    )


def ngo_details(request):
    return render(request, "main_app/ngo_details.html", {"title": "ngo_details"})


def gallery(request):
    return render(request, "main_app/gallery.html", {"title": "Gallery"})


def FAQ(request):
    return render(request, "main_app/FAQ.html", {"title": "FAQ"})


def women_laws(request):
    return render(request, "main_app/women_laws.html", {"title": "women_laws"})


def developers(request):
    return render(request, "main_app/developers.html", {"title": "developers"})


def women_rights(request):
    return render(request, "main_app/women_rights.html", {"title": "women_rights"})


def page_not_found(request, exception):
    return render(request, "main_app/404.html")


def check_username(request):
    username = request.GET.get("name")
    if User.objects.filter(username=username).exists():
        return JsonResponse({"exists": "yes"})
    return JsonResponse({"exists": "no"})


def check_email(request):
    email = request.GET.get("email")
    if User.objects.filter(email=email).exists():
        return JsonResponse({"exists": "yes"})
    return JsonResponse({"exists": "no"})


def contact_user(request):
    if request.method == "POST":
        message_name = request.POST["message-name"]
        message_email = request.POST["message-email"]
        message = request.POST["message"]

        # send an email
        send_email(  # noqa
            message_name,  # subject
            message,  # message
            message_email,  # from email
            ["rescue@gmail.com"],  # To Email
        )

        return render(
            request, "main_app/contact_user.html", {"message_name": message_name}
        )

    else:
        return render(request, "main_app/contact_user.html", {})
