from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver



class CustomUser(AbstractUser):
    user_type=models.CharField(default=1,max_length=200)
    status=models.IntegerField(default=0)

class Department(models.Model):
    name = models.CharField(max_length=100)
    description=models.TextField(max_length=600,null=True)

class Doctor(models.Model):
    department=models.ForeignKey(Department,on_delete=models.CASCADE,null=True)
    user=models.ForeignKey(CustomUser,on_delete=models.CASCADE,null=True)
    Age=models.IntegerField()
    Address=models.TextField()
    Phone_number=models.CharField(max_length=255)
    Image=models.ImageField(upload_to='image/',null=True,blank=True)
    registration_source = models.CharField(max_length=20, choices=(('admin', 'Admin'), ('external', 'External')), default='external')

class Patient(models.Model):
    department=models.ForeignKey(Department,on_delete=models.CASCADE,null=True)
    user=models.ForeignKey(CustomUser,on_delete=models.CASCADE,null=True)
    patient_id = models.CharField(max_length=10, unique=True, editable=False)
    Age=models.IntegerField()
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    Address=models.TextField()
    Phone_number=models.CharField(max_length=255)
    Image=models.ImageField(upload_to='image/',null=True,blank=True)

class Appointment(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    appointment_date = models.DateField()
    reason_for_visit = models.TextField()
    STATUS_CHOICES = [
        (0, 'Pending'),
        (1, 'Approved'),
        (2, 'Rejected'),
    ]
    status = models.IntegerField(choices=STATUS_CHOICES, default=0)  # Default is "Pending"
    op_number = models.CharField(max_length=20, null=True, blank=True)
    medicines = models.TextField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    TIME_SLOT_CHOICES = [
        ('9AM-10AM', '9AM-10AM'),
        ('10AM-11AM', '10AM-11AM'),
        ('11AM-12PM', '11AM-12PM'),
        ('2PM-3PM', '2PM-3PM'),
        ('3PM-4PM', '3PM-4PM'),
    ]
    time_slot = models.CharField(max_length=20, choices=TIME_SLOT_CHOICES, null=True, blank=True)

class Notification(models.Model):
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

@receiver(post_save, sender=Appointment)
def create_appointment_notification(sender, instance, created, **kwargs):
    # Check if the appointment's status is set to "Approved" (status = 1)
    if instance.status == 1:  # Status is Approved
        # Create a notification for the doctor
        Notification.objects.create(
            doctor=instance.doctor,
            message=f"You have received a new appointment with patient {instance.patient.user.first_name} for {instance.appointment_date} at {instance.time_slot}."
        )


