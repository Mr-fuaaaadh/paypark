import uuid
from django.db import models
from django.contrib.auth.hashers import make_password
from django.utils.timezone import now
from datetime import timedelta


class Customer(models.Model):
    _id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100, null=False)
    email = models.EmailField(max_length=100, unique=True, null=False)
    phone_number = models.CharField(max_length=15, null=False)  
    vehicle_number = models.CharField(max_length=50, unique=True, null=False)
    model_number = models.CharField(max_length=100, null=False)
    password = models.CharField(max_length=255, null=False)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True, db_index=True)

    def save(self, *args, **kwargs):
        if not self.password.startswith('pbkdf2_'): 
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name
    

class OTP(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)  

    class Meta:
        db_table = "OTP"




