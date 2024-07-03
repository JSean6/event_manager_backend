from django.contrib import admin
from auth_app.models import CustomUser, Event

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(Event)
