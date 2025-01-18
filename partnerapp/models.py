from django.db import models
from django.contrib.auth.hashers import make_password
import uuid

# Create your models here.
class PlotOnwners(models.Model):
    ownerID = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    owner_name = models.CharField(max_length=100, null=False)
    owner_email = models.CharField(max_length=100,null=False, unique=True)
    owner_phone = models.CharField(max_length=15, unique=True, null=False)
    latitude = models.DecimalField(max_digits=10, decimal_places=8, null=False)
    longitude = models.DecimalField(max_digits=11, decimal_places=8, null=False)
    ownership_type = models.CharField(
        max_length=10,
        choices=[('owner', 'Owner'), ('lease', 'Lease')],
        null=False
    )
    account_number = models.CharField(max_length=20, null=False)
    ifsc_code = models.CharField(max_length=11, null=False)
    password = models.CharField(max_length=255, null=False)
    role = models.CharField(
        max_length=10,
        choices=[('admin', 'Admin'), ('operator', 'Operator')],
        default='operator'
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.owner_name

    def save(self, *args, **kwargs):
        if not self.password.startswith('pbkdf2_'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)



class Images(models.Model):
    station = models.ForeignKey(PlotOnwners, on_delete=models.CASCADE,related_name="images")
    image = models.ImageField(upload_to="parking_station/")
    
    class Meta:
        db_table = "Parking_Station_Images"
    
    def __str__(self):
        return f"Image for Station: {self.station.owner_name if self.station else 'Unknown Station'}"



class AdminOTP(models.Model):
    user = models.ForeignKey(PlotOnwners, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta :
        db_table = "admin_otp"



class Vehicle(models.Model):
    vehicle_type_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)  
    name = models.CharField(max_length=50,unique=True)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return self.name
