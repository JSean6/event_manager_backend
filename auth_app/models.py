from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
import cloudinary.uploader
from cloudinary.models import CloudinaryField

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('superadmin', 'Super Admin'),
        ('admin', 'Admin'),
        ('staff', 'Staff'),
        ('user', 'User'),
    )

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')

class Events(models.Model):
    image = CloudinaryField("image",null=True)
    title = models.CharField(max_length=100)
    category = models.CharField(max_length=100)
    venue = models.CharField(max_length=100)
    description = models.TextField()
    startDate = models.DateField()
    endDate = models.DateField()
    duration = models.CharField(max_length=10, null=True)
    time = models.CharField(max_length=10, null=True)
    tickets = models.IntegerField(null=True)
    price_of_ticket = models.IntegerField(null=True)

    def __str__(self):
        return self.title


class Tickets(models.Model):
    title = models.CharField(max_length=100)
    category = models.CharField(max_length=100)
    duration = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    number_of_tickets = models.IntegerField()
    
    def __str__(self):
        return f"{self.name} - {self.title}"
    
class Contacts(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    message = models.CharField(max_length=100)

    def __str__(self):
        return self.name
class Vendors(models.Model):
    image = CloudinaryField("image",null=True)
    Comapany_name = models.CharField(max_length=100)
    service = models.CharField(max_length=100)
    working_hours = models.CharField(max_length=100)
    rates = models.CharField(max_length=100)
    availability = models.CharField(max_length=100)
    contact = models.IntegerField()

    def __str__(self):
        return self.Comapany_name





















