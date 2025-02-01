from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Appointment, Notification

@receiver(post_save, sender=Appointment)
def create_appointment_notification(sender, instance, created, **kwargs):
    if instance.status == 1 and created:  # When the appointment status is approved
        message = f"New appointment from {instance.patient.user.first_name} has been approved."
        Notification.objects.create(doctor=instance.doctor, message=message)
