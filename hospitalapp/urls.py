from django.urls import path,include
from .import views

urlpatterns = [
    path('',views.home,name="home"),
    path('log',views.log,name="log"),
    path('doctor',views.doctor,name="doctor"),
    path('patient',views.patient,name="patient"),
    path('admin',views.admin,name="admin"),
    path('add_department',views.add_department,name="add_department"),
    path('add_departmentdb',views.add_departmentdb,name="add_departmentdb"),
    path('manage_department',views.manage_department,name="manage_department"),
    path('delete_department/<int:lk>',views.delete_department,name="delete_department"),
    path('login1',views.login1,name="login1"),
    path('add_doctor',views.add_doctor,name="add_doctor"),
    path('adp',views.adp,name="adp"),
    path('approve/<int:k>', views.approve, name="approve"),
    path('disapprove/<int:k>', views.disapprove, name="disapprove"),
    path('admin_view',views.admin_view,name="admin_view"),
    path('register_patient/',views.register_patient, name='register_patient'),
    path('admin_register_patient', views.admin_register_patient, name='admin_register_patient'),   
    path('doc_table',views.doc_table, name='doc_table'),
    path('dlt/<int:lk>',views.dlt,name="dlt"),
    path('patient_table',views.patient_table, name='patient_table'),
    path('delete/<int:vk>',views.delete,name="delete"),
    path('logout/', views.logout_view, name='logout'),
    path('doctor_dashboard',views.doctor_dashboard,name="doctor_dashboard"),
    path('patient_dashboard',views.patient_dashboard,name="patient_dashboard"),
    path('doctor_profile',views.doctor_profile,name="doctor_profile"),
    path('reset_password/',views.reset_password, name='reset_password'),
    path('patient_profile',views.patient_profile,name="patient_profile"),
    path('reset_password2/',views.reset_password2, name='reset_password2'),
    path('book_appointment/', views.book_appointment, name='book_appointment'),
    path('appointment_success/', views.appointment_success, name='appointment_success'),
    path('manage_appointments/', views.manage_appointments, name='manage_appointments'),
    path('patient_appointments/', views.patient_appointments, name='patient_appointments'),
    path('doctor/appointments/', views.doctor_appointments, name='doctor_appointments'),
    path('doctor/appointments/today/', views.todays_appointments, name='todays_appointments'),
    path('doctor/appointments/upcoming/', views.upcoming_appointments, name='upcoming_appointments'),
    path('attend_appointment/<int:appointment_id>/', views.attend_appointment, name='attend_appointment'),
    path('patient_details/<int:patient_id>/', views.patient_details, name='patient_details'),
    path('consultations/', views.consultation_details, name='consultation_details'),
    path('consultation-details/<int:appointment_id>/', views.view_consultation_detail, name='view_consultation_detail'),
    path('consultation-detail/', views.patient_consultation_details, name='patient_consultation_details'),
    path('view-consultation/<int:appointment_id>/', views.view_patient_consultation_details, name='view_patient_consultation_details'),
    path('mark_notifications_as_read/', views.mark_notifications_as_read, name='mark_notifications_as_read'),
    path('edit-patient-profile/', views.edit_patient_profile, name='edit_patient_profile'),
    path('edit-doctor-profile/', views.edit_doctor_profile, name='edit_doctor_profile'),
    path('add_patient/', views.add_patient_view, name='add_patient'),
    path('add_doctor_admin', views.add_doctor_admin, name='add_doctor_admin'),
    path('admin_register_doctor', views.admin_register_doctor, name='admin_register_doctor'), 
    

    

]