from .models import Appointment

def appointment_count(request):
    if request.user.is_authenticated and request.user.is_staff:
        pending_appointments_count = Appointment.objects.filter(status=0).count()
        return {'pending_appointments_count': pending_appointments_count}
    return {}
