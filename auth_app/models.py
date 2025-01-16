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

class Personnel(models.Model):
    image = CloudinaryField("image",null=True)
    id = models.CharField(max_length=100, primary_key=True)
    firstName = models.CharField(max_length=100)
    secondName = models.CharField(max_length=100)
    phoneNumber = models.IntegerField(null=True)
    emailAddress = models.EmailField()
    dateJoined = models.DateField()
    averageRating = models.IntegerField(null=True)
    uniformColor = models.CharField(max_length=100, null=True)
    workPermit = models.IntegerField(null=True)

    def __str__(self):
        return self.title
    
class Contacts(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    message = models.CharField(max_length=100)

    def __str__(self):
        return self.name






















