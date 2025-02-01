from django.shortcuts import render,redirect
from .models import Department
from .models import Doctor
from .models import Patient
from .models import Appointment,Notification
from django.contrib import messages
from django.contrib.auth.models import AbstractUser
from .models import CustomUser
from django.contrib.auth import login, authenticate
from django.utils.crypto import get_random_string
import random
import string
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib import auth
import logging
from django.contrib.auth import update_session_auth_hash
import re
from django.contrib.admin.views.decorators import staff_member_required
import uuid 
from datetime import date
from django.shortcuts import render, get_object_or_404, redirect
from django.db.models import Q
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.core.exceptions import ValidationError
from django.core.validators import validate_email




def home(request):
    return render(request,'home.html')

def log(request):
    return render(request,'login.html')

def doctor(request):
    department=Department.objects.all()
    return render(request,'doctor.html',{'department':department})

def patient(request):
    return render(request,'patient.html')

def add_patient_view(request):
    return render(request,'add_patient.html')

def add_doctor_admin(request):
    department=Department.objects.all()
    return render(request,'add_doctor_admin.html',{'department':department})

def admin(request):
    return render(request,'admin.html')

def add_department(request):
    return render(request,'add_department.html')

def add_departmentdb(request):
    if request.method=="POST":
        department_name=request.POST['Dname']
        description=request.POST['Description']
        department=Department(name=department_name,description=description)
        department.save()
        messages.success(request, 'Department added successfully.')
        return redirect('add_department')
    
def manage_department(request):
    department=Department.objects.all()
    return render(request,'manage_department.html',{'department':department})

def delete_department(request,lk):
    dept=Department.objects.get(id=lk)
    dept.delete()
    return redirect('manage_department')

def login1(request):
    if request.method=="POST":
        username=request.POST['username']
        password=request.POST['password']
        user=authenticate(username=username,password=password)

        if user is not None:
            if user.user_type=='1':
                login(request,user)
                return redirect('admin_view')
            elif user.user_type=='2':
                auth.login(request,user)
                return redirect('doctor_dashboard')
            elif user.user_type=='3':
                auth.login(request,user)
                return redirect('patient_dashboard')



def add_doctor(request):
    if request.method == "POST":
        firstname = request.POST['Fname']
        lastname = request.POST['Lname']
        username = request.POST['Uname']
        Age = request.POST['age']
        Address=request.POST['address']
        email = request.POST['email']
        contact = request.POST['phone']
        user_type=request.POST['text']
        sel1 = request.POST['sel']
        department2 = Department.objects.get(id=sel1)
        Image = request.FILES.get('photo')

        if CustomUser.objects.filter(username=username).exists():
            messages.success(request, 'Username already exists. Please choose another.')
            return render(request, 'doctor.html')

        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            messages.success(request, 'Email already exists. Please choose another.')
            return render(request, 'doctor.html')

        # Validate email format
        try:
            validate_email(email)
            if not email.endswith('.com'):
                raise ValidationError("Invalid email format.")
        except ValidationError:
            messages.success(request, 'Enter a valid email ID.')
            return render(request, 'doctor.html')

        # Validate mobile number format (exactly 10 digits)
        if not re.match(r'^\d{10}$', contact):
            messages.success(request, 'Enter a valid Mobile number.')
            return render(request, 'doctor.html')


        user = CustomUser.objects.create_user(
            username=username,
            first_name=firstname,
            last_name=lastname,
            email=email,
            user_type=user_type)

        user.save()

        doctor = Doctor(
            user=user,
            department=department2,
            Age=Age,
            Address=Address,
            Phone_number=contact,
            Image=Image
        )
        doctor.save()
        messages.success(request, 'Doctor added successfully..wait for admin approval')
        return render(request, 'doctor.html')

def admin_register_doctor(request):
    if request.method == "POST":
        firstname = request.POST['Fname']
        lastname = request.POST['Lname']
        username = request.POST['Uname']
        Age = request.POST['age']
        Address = request.POST['address']
        email = request.POST['email']
        contact = request.POST['phone']
        user_type = request.POST['text']
        sel1 = request.POST['sel']
        department2 = Department.objects.get(id=sel1)
        Image = request.FILES.get('photo')

        if CustomUser.objects.filter(username=username).exists():
            messages.success(request, 'Username already exists. Please choose another.')
            return render(request, 'add_patient.html')

        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            messages.success(request, 'Email already exists. Please choose another.')
            return render(request, 'add_patient.html')

        # Validate email format
        try:
            validate_email(email)
            if not email.endswith('.com'):
                raise ValidationError("Invalid email format.")
        except ValidationError:
            messages.success(request, 'Enter a valid email ID.')
            return render(request, 'add_patient.html')

        # Validate mobile number format (exactly 10 digits)
        if not re.match(r'^\d{10}$', contact):
            messages.success(request, 'Enter a valid Mobile number.')
            return render(request, 'add_patient.html')

        # Generate a 6-digit random password
        password = str(random.randint(100000, 999999))

        # Create the user
        user = CustomUser.objects.create_user(
            username=username,
            first_name=firstname,
            last_name=lastname,
            email=email,
            password=password,
            user_type=user_type
        )

        user.save()

        # Create the doctor record
        doctor = Doctor(
            user=user,
            department=department2,
            Age=Age,
            Address=Address,
            Phone_number=contact,
            Image=Image,
            registration_source='admin'
        )
        doctor.save()

        # Send email with username, password, and email
        subject = 'Doctor Registration Details'
        message = (
            f"Dear {firstname} {lastname},\n\n"
            f"Your account has been created successfully.\n\n"
            f"Username: {username}\n"
            f"Password: {password}\n"
            f"Email: {email}\n\n"
            f"Please log in and change your password as soon as possible.\n\n"
            f"Thank you!"
        )
        send_mail(subject, message, settings.EMAIL_HOST_USER, [email], fail_silently=False)

        # Add success message and redirect
        # messages.success(request, 'Doctor added successfully. Login details have been sent to the doctor\'s email.')
        return redirect('doc_table') 

    return render(request, 'add_doctor_admin.html')

    
def adp(request):
    # Fetch only externally registered doctors
    doctors = Doctor.objects.filter(user__user_type='2', registration_source='external')
    return render(request, 'approvedisapprove.html', {'us': doctors})

def approve(request,k):
    usr=CustomUser.objects.get(id=k)
    if usr.user_type=='2':
        usr.status='1'
        usr.save()
        passw=CustomUser.objects.get(id=k)
        doc=Doctor.objects.get(user=k)
        password=str(random.randint(100000,999999))
        passw.set_password(password)
        passw.save()
        du=doc.user.username
        de=doc.user.email
        subject='Admin Approved'
        message='username:'+str(du)+"\n"+'password:'+str(password)+"\n"+'email:'+str(de)
        send_mail(subject,message,settings.EMAIL_HOST_USER,{usr.email})
        messages.info(request,'Doctor approved')
        return redirect('adp')

def disapprove(request, k):
    usr = CustomUser.objects.get(id=k)
    if usr.user_type == '2':
        usr.status=0
        usr.save()
        doc=Doctor.objects.get(user=k)
        doc.delete()
        passw=CustomUser.objects.get(id=k)
        passw.delete()
        subject='Admin Disapproved'
        message='Admin Disapproved Your Registration..Try Again Later!'
        send_mail(subject,message,settings.EMAIL_HOST_USER,{usr.email})
        messages.info(request,'Doctor disapproved')
        return redirect('adp')
    
def admin_view(request):
    # Count unapproved users with user_type='2' and registration_source='external'
    unapproved_count = CustomUser.objects.filter(
        status=0, 
        user_type='2', 
        doctor__registration_source='external'  # Join with Doctor model
    ).count()

    # Pass the updated count to the template context
    context = {
        'unapproved_count': unapproved_count,
        # Include other context data as needed
    }
    return render(request, 'admin.html', context)




def register_patient(request):
    if request.method == 'POST':
        # Get form data
        first_name = request.POST['Fname']
        last_name = request.POST['Lname']
        username = request.POST['Uname']
        age = request.POST['age']
        gender = request.POST['gender']
        address = request.POST['address']
        email = request.POST['email']
        phone_number = request.POST['phone']
        user_type=request.POST['text']
        Image = request.FILES.get('photo')

        if CustomUser.objects.filter(username=username).exists():
            messages.success(request, 'Username already exists. Please choose another.')
            return render(request, 'patient.html')

        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            messages.success(request, 'Email already exists. Please choose another.')
            return render(request, 'patient.html')

        # Validate email format
        try:
            validate_email(email)
            if not email.endswith('.com'):
                raise ValidationError("Invalid email format.")
        except ValidationError:
            messages.success(request, 'Enter a valid email ID.')
            return render(request, 'patient.html')

        # Validate mobile number format (exactly 10 digits)
        if not re.match(r'^\d{10}$', phone_number):
            messages.success(request, 'Enter a valid Mobile number.')
            return render(request, 'patient.html')
        
        # Generate a unique 10-character alphanumeric patient ID
        patient_id = get_random_string(10, allowed_chars=string.ascii_uppercase + string.digits)
        
        # Generate a random 6-digit password
        password = str(random.randint(100000, 999999))
        
        # Create the CustomUser instance
        user = CustomUser.objects.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            user_type=user_type
        )

        # Save the password securely in the CustomUser instance
        user.set_password(password)
        user.save()

        # Create the Patient instance without assigning a department
        patient = Patient.objects.create(
            user=user,
            patient_id=patient_id,
            Age=age,
            gender=gender,
            Address=address,
            Phone_number=phone_number,
            Image=Image
        )
        patient.save()

        # Send an email with the patient ID and password
        subject = 'Patient Registration Details'
        message = f'Hello {first_name},\n\nYour Patient ID is {patient_id},Your Username is {username} and Your Password is {password}.\nPlease change your password upon first login.\n\nThank you!'
        send_mail(subject, message, settings.EMAIL_HOST_USER,  [user.email], fail_silently=False)

        messages.success(request, 'Patient registered successfully. Check your email for login details.')
        return redirect('patient')  # Redirect to a success page
    else:
        return render(request, 'patient.html') 
    
def admin_register_patient(request):
    if request.method == 'POST':
        first_name = request.POST['Fname']
        last_name = request.POST['Lname']
        username = request.POST['Uname']
        age = request.POST['age']
        gender = request.POST['gender']
        address = request.POST['address']
        email = request.POST['email']
        phone_number = request.POST['phone']
        user_type = request.POST['text']
        Image = request.FILES.get('photo')

        if CustomUser.objects.filter(username=username).exists():
            messages.success(request, 'Username already exists. Please choose another.')
            return render(request, 'add_patient.html')

        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            messages.success(request, 'Email already exists. Please choose another.')
            return render(request, 'add_patient.html')

        # Validate email format
        try:
            validate_email(email)
            if not email.endswith('.com'):
                raise ValidationError("Invalid email format.")
        except ValidationError:
            messages.success(request, 'Enter a valid email ID.')
            return render(request, 'add_patient.html')

        # Validate mobile number format (exactly 10 digits)
        if not re.match(r'^\d{10}$', phone_number):
            messages.success(request, 'Enter a valid Mobile number.')
            return render(request, 'add_patient.html')

        # Generate unique patient ID and password
        patient_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        password = str(random.randint(100000, 999999))

        # Create user and patient
        user = CustomUser.objects.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            user_type=user_type
        )
        user.set_password(password)
        user.save()

        patient = Patient.objects.create(
            user=user,
            patient_id=patient_id,
            Age=age,
            gender=gender,
            Address=address,
            Phone_number=phone_number,
            Image=Image
        )
        patient.save()

        subject = 'Patient Registration Details'
        message = f'Hello {first_name},\n\nYour Patient ID is {patient_id},Your Username is {username} and Your Password is {password}.\nPlease change your password upon first login.\n\nThank you!'
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email], fail_silently=False)

        
        return redirect('patient_table')  # Redirect to the patient list in admin panel
    else:
        return render(request, 'add_patient.html')



    
@login_required
def doc_table(request):
    doctor = Doctor.objects.all()
    return render(request, 'doc_table.html', {'doc': doctor})

def dlt(request,lk):
    doc2=Doctor.objects.get(id=lk)
    doc2.delete()
    doc2.user.delete()
    messages.success(request, 'Doctor deleted successfully.')
    return redirect('doc_table')

@login_required
def patient_table(request):
    patient = Patient.objects.all()
    return render(request, 'patient_table.html', {'pat': patient})

def delete(request,vk):
    pat2=Patient.objects.get(id=vk)
    pat2.delete()
    pat2.user.delete()
    messages.success(request, 'Patient deleted successfully.')
    return redirect('patient_table')

def logout_view(request):
    logout(request)
    return redirect('log') 
 
@login_required
def doctor_dashboard(request):
    if request.user.is_authenticated:
        try:
            doctor = Doctor.objects.get(user=request.user)
            doctor_name = doctor.user.first_name

            # Get unread notifications count
            unread_notifications = Notification.objects.filter(doctor=doctor, read=False)
            unread_notifications_count = unread_notifications.count()

            # Get all notifications, ordered by latest first
            all_notifications = Notification.objects.filter(doctor=doctor).order_by('-created_at')

            return render(request, 'doctor_dashboard.html', {
                'doctor': doctor,
                'doctor_name': doctor_name,
                'unread_notifications_count': unread_notifications_count,
                'unread_notifications': all_notifications  # Pass all notifications, latest first
            })
        except Doctor.DoesNotExist:
            return redirect('log')  # Redirect to login page if doctor doesn't exist
    else:
        return redirect('log')
    
@csrf_exempt
def mark_notifications_as_read(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            doctor_id = data.get('doctor_id')
            if doctor_id:
                doctor = Doctor.objects.get(id=doctor_id)
                Notification.objects.filter(doctor=doctor, read=False).update(read=True)
                return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    return JsonResponse({'success': False}, status=400)
    
@login_required
def patient_dashboard(request):
    if request.user.is_authenticated:
        try:
            patient = Patient.objects.get(user=request.user)
            patient_name = patient.user.first_name
            return render(request, 'patient_dashboard.html', {'patient': patient, 'patient_name': patient_name})
        except Doctor.DoesNotExist:
            return redirect('log')
    else:
        return redirect('log')
    
def doctor_profile(request):
    if request.user.is_authenticated:
        try:
            # Get the doctor profile associated with the logged-in user
            doctor = Doctor.objects.get(user=request.user)
            # Pass doctor data to template
            return render(request, 'doctor_profile.html', {'doctor': doctor})
        except Doctor.DoesNotExist:
            # Handle the case where the doctor is not found
            return redirect('log')  # Redirect to login or another appropriate page
    else:
        return redirect('log')  # Redirect if not logged in
    
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

@login_required
def edit_doctor_profile(request):
    doctor = get_object_or_404(Doctor, user=request.user)
    user = doctor.user  # Get the related User model

    if request.method == 'POST':
        # Get data from the form submission
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        age = request.POST.get('age')
        address = request.POST.get('address')
        phone_number = request.POST.get('phone_number')
        image = request.FILES.get('image')

        # Validation
        # 1. Check if username already exists and is different from the current user's username
        if username != user.username and CustomUser.objects.filter(username=username).exists():
            messages.success(request, "Username already exists. Please choose a different one.")
            return render(request, 'edit_doctor_profile.html', {'doctor': doctor})

        # 2. Validate email format and uniqueness
        try:
            validate_email(email)  # Validate format
        except ValidationError:
            messages.success(request, "Invalid email format.")
            return render(request, 'edit_doctor_profile.html', {'doctor': doctor})

        if email != user.email and CustomUser.objects.filter(email=email).exists():
            messages.success(request, "Email already exists. Please choose a different one.")
            return render(request, 'edit_doctor_profile.html', {'doctor': doctor})

        # 3. Validate phone number length
        if not phone_number.isdigit() or len(phone_number) != 10:
            messages.success(request, "Phone number must be exactly 10 digits.")
            return render(request, 'edit_doctor_profile.html', {'doctor': doctor})

        # Save changes
        # Update User model
        user.first_name = first_name
        user.last_name = last_name
        user.username = username
        user.email = email
        user.save()

        # Update Doctor model
        doctor.Age = age
        doctor.Address = address
        doctor.Phone_number = phone_number
        if image:
            doctor.Image = image
        doctor.save()

        
        return redirect('doctor_profile')  # Redirect to the profile page

    return render(request, 'edit_doctor_profile.html', {'doctor': doctor})

    
@login_required
def reset_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Check if the current password is correct
        if not request.user.check_password(current_password):
            messages.error(request, "Current password is incorrect.")
            return redirect('reset_password')

        # Check if the new password and confirmation match
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect('reset_password')

        # Password complexity check
        if not is_password_valid(new_password):
            messages.error(request, "Password must be at least 6 characters long and contain at least one uppercase letter, one digit, and one special character.")
            return redirect('reset_password')

        # Update the password if validations pass
        request.user.set_password(new_password)
        request.user.save()

        # Update the session so the user remains logged in
        update_session_auth_hash(request, request.user)
        messages.success(request, "Your password has been reset successfully.")
        return redirect('reset_password')  # Replace with the page you want to redirect to
    
    return render(request, 'reset_password.html')

def is_password_valid(password):
    # Check the password against the complexity requirements
    if (len(password) >= 6 and
        re.search(r'[A-Z]', password) and     # At least one uppercase letter
        re.search(r'\d', password) and        # At least one digit
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):  # At least one special character
        return True
    return False

def patient_profile(request):
    if request.user.is_authenticated:
        try:
            # Get the doctor profile associated with the logged-in user
            patient = Patient.objects.get(user=request.user)
            # Pass doctor data to template
            return render(request, 'patient_profile.html', {'patient': patient})
        except Patient.DoesNotExist:
            # Handle the case where the doctor is not found
            return redirect('log')  # Redirect to login or another appropriate page
    else:
        return redirect('log')  # Redirect if not logged in
    
@login_required
def edit_patient_profile(request):
    patient = get_object_or_404(Patient, user=request.user)
    user = patient.user  # Get the related User model

    if request.method == 'POST':
        # Get data from the form submission
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        age = request.POST.get('age')
        gender = request.POST.get('gender')
        address = request.POST.get('address')
        phone_number = request.POST.get('phone_number')
        image = request.FILES.get('image')

        # Validation
        # 1. Check if username already exists and is different from the current user's username
        if username != user.username and CustomUser.objects.filter(username=username).exists():
            messages.success(request, "Username already exists. Please choose a different one.")
            return render(request, 'edit_patient_profile.html', {'patient': patient})

        # 2. Validate email format and uniqueness
        try:
            validate_email(email)  # Validate format
        except ValidationError:
            messages.success(request, "Invalid email format.")
            return render(request, 'edit_patient_profile.html', {'patient': patient})

        if email != user.email and CustomUser.objects.filter(email=email).exists():
            messages.success(request, "Email already exists. Please choose a different one.")
            return render(request, 'edit_patient_profile.html', {'patient': patient})

        # 3. Validate phone number length
        if not phone_number.isdigit() or len(phone_number) != 10:
            messages.success(request, "Phone number must be exactly 10 digits.")
            return render(request, 'edit_patient_profile.html', {'patient': patient})

        # Update User model
        user.first_name = first_name
        user.last_name = last_name
        user.username = username
        user.email = email
        user.save()

        # Update Patient model
        patient.Age = age
        patient.gender = gender
        patient.Address = address
        patient.Phone_number = phone_number
        if image:
            patient.Image = image
        patient.save()

        return redirect('patient_profile')  # Redirect to the profile page

    return render(request, 'edit_patient_profile.html', {'patient': patient})
    
@login_required
def reset_password2(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Check if the current password is correct
        if not request.user.check_password(current_password):
            messages.error(request, "Current password is incorrect.")
            return redirect('reset_password2')

        # Check if the new password and confirmation match
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect('reset_password2')

        # Password complexity check
        if not is_password_valid(new_password):
            messages.error(request, "Password must be at least 6 characters long and contain at least one uppercase letter, one digit, and one special character.")
            return redirect('reset_password2')

        # Update the password if validations pass
        request.user.set_password(new_password)
        request.user.save()

        # Update the session so the user remains logged in
        update_session_auth_hash(request, request.user)
        messages.success(request, "Your password has been reset successfully.")
        return redirect('reset_password2')  # Replace with the page you want to redirect to
    
    return render(request, 'reset_password2.html')

def is_password_valid(password):
    # Check the password against the complexity requirements
    if (len(password) >= 6 and
        re.search(r'[A-Z]', password) and     # At least one uppercase letter
        re.search(r'\d', password) and        # At least one digit
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):  # At least one special character
        return True
    return False

@login_required
def book_appointment(request):
    patient = Patient.objects.get(user=request.user)
    departments = Department.objects.all()
    doctors = None
    selected_department = None
    available_slots = []

    all_slots = ['9AM-10AM', '10AM-11AM', '11AM-12PM', '2PM-3PM', '3PM-4PM']

    if request.method == 'POST':
        selected_department = request.POST.get('department')

        if selected_department:
            doctors = Doctor.objects.filter(department_id=selected_department)

        if 'book_appointment' in request.POST:
            department_id = request.POST.get('department')
            doctor_id = request.POST.get('doctor')
            appointment_date = request.POST.get('appointment_date')
            time_slot = request.POST.get('time_slot')
            reason_for_visit = request.POST.get('reason_for_visit')

            department = Department.objects.get(id=department_id)
            doctor = Doctor.objects.get(id=doctor_id)

            # Check the booking limit for the selected doctor and date
            existing_appointments = Appointment.objects.filter(
                doctor=doctor,
                appointment_date=appointment_date,
            )

            # Exclude rejected appointments from the limit check
            non_rejected_appointments = existing_appointments.exclude(status=2)

            if non_rejected_appointments.count() >= 5:
                return JsonResponse({'error': 'No slots available for this doctor on the selected date.'}, status=400)

            # Create and save the appointment
            Appointment.objects.create(
                patient=patient,
                department=department,
                doctor=doctor,
                appointment_date=appointment_date,
                time_slot=time_slot,
                reason_for_visit=reason_for_visit,
                status=0  # Set status as Pending
            )
            return redirect('appointment_success')

    if request.method == 'GET' and 'doctor' in request.GET and 'date' in request.GET:
        doctor_id = request.GET.get('doctor')
        date_selected = request.GET.get('date')

        if doctor_id and date_selected:
            doctor = Doctor.objects.get(id=doctor_id)
            booked_slots = Appointment.objects.filter(
                doctor=doctor,
                appointment_date=date_selected,
            ).values_list('time_slot', flat=True)

            # Get rejected appointments and free up those slots
            rejected_appointments = Appointment.objects.filter(
                doctor=doctor,
                appointment_date=date_selected,
                status=2  # Rejected
            ).values_list('time_slot', flat=True)

            # Exclude approved appointments (status=1) from available slots
            approved_appointments = Appointment.objects.filter(
                doctor=doctor,
                appointment_date=date_selected,
                status=1  # Approved
            ).values_list('time_slot', flat=True)

            # Combine the rejected slots and free slots and exclude the approved ones
            available_slots = [slot for slot in all_slots if slot not in booked_slots and slot not in approved_appointments]

            return JsonResponse({'available_slots': available_slots})

    return render(request, 'book_appointment.html', {
        'patient': patient,
        'departments': departments,
        'doctors': doctors,
        'selected_department': selected_department,
        'available_slots': available_slots,
    })





@login_required
def appointment_success(request):
    return render(request, 'appointment_success.html')

@staff_member_required
def manage_appointments(request):
    appointments = Appointment.objects.all()  # Fetch all appointments
    pending_appointments_count = Appointment.objects.filter(status=0).count()  # Count pending approvals

    if request.method == 'POST':
        appointment_id = request.POST.get('appointment_id')
        action = request.POST.get('action')  # 'approve' or 'reject'
        appointment = Appointment.objects.get(id=appointment_id)

        if action == 'approve':
            appointment.status = 1  # Approved
            if not appointment.op_number:  # Generate OP number if not already generated
                appointment.op_number = f"OP-{uuid.uuid4().hex[:8].upper()}"
        elif action == 'reject':
            appointment.status = 2  # Rejected

        appointment.save()
        return redirect('manage_appointments')

    return render(request, 'manage_appointments.html', {
        'appointments': appointments,
        'pending_appointments_count': pending_appointments_count,
    })

@login_required
def patient_appointments(request):
    patient = Patient.objects.get(user=request.user)
    appointments = Appointment.objects.filter(patient=patient)
    return render(request, 'your_appointments.html', {'appointments': appointments})

@login_required
def doctor_appointments(request):
    """Renders the main page with links to Today's and Upcoming Appointments."""
    return render(request, 'doctor_appointments.html')

@login_required
def todays_appointments(request):
    """Fetches and displays today's appointments."""
    doctor = Doctor.objects.get(user=request.user)  # Get the doctor associated with the logged-in user
    today = date.today()
    # Include appointments with status Approved (1) or Consulted (3)
    appointments = Appointment.objects.filter(
        doctor=doctor, 
        appointment_date=today, 
        status__in=[1, 3]
    )

    return render(request, 'todays_appointments.html', {'appointments': appointments})

@login_required
def upcoming_appointments(request):
    """Fetches and displays upcoming appointments."""
    doctor = Doctor.objects.get(user=request.user)  # Get the doctor associated with the logged-in user
    today = date.today()
    appointments = Appointment.objects.filter(doctor=doctor, appointment_date__gt=today, status=1)

    return render(request, 'upcoming_appointments.html', {'appointments': appointments})

def attend_appointment(request, appointment_id):
    appointment = get_object_or_404(Appointment, id=appointment_id)

    if request.method == 'POST':
        medicines = request.POST.get('medicines')
        description = request.POST.get('description')

        # Save consultation details (add fields in Appointment if needed)
        appointment.status = 3  # Mark as consulted
        appointment.medicines = medicines  # Add this field in the model if needed
        appointment.description = description  # Add this field in the model if needed
        appointment.save()

        return redirect('todays_appointments')

    return render(request, 'attend_appointment.html', {'appointment': appointment})

def patient_details(request, patient_id):
    patient = get_object_or_404(Patient, id=patient_id)
    return render(request, 'patient_details.html', {'patient': patient})

def consultation_details(request):
    """View to display consultation details in the admin panel."""
   
    consultations = Appointment.objects.filter(Q(status=3) | Q(status=1)) # Only consulted patients

    return render(request, 'consultation_details.html', {'consultations': consultations})

def view_consultation_detail(request, appointment_id):
    """View to display specific consultation details."""
    consultation = get_object_or_404(Appointment, id=appointment_id, status=3)  # Ensure only consulted
    return render(request, 'view_consultation_detail.html', {'consultation': consultation})

def patient_consultation_details(request):
    """Fetch and display consultation details for the logged-in patient."""
    patient = Patient.objects.get(user=request.user)  # Assuming the user has a 'patient' profile
    
    # Fetch the patient's consultations
    consultations = Appointment.objects.filter(patient=patient).filter(Q(status=3) | Q(status=1))
    
    return render(request, 'patient_consultation_details.html', {'consultations': consultations})

def view_patient_consultation_details(request, appointment_id):
    """View to display full consultation details for the patient."""
    appointment = get_object_or_404(Appointment, id=appointment_id)
    
    return render(request, 'view_patient_consultation_details.html', {'appointment': appointment})


