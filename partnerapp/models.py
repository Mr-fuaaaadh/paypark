from django.db import models
from django.contrib.auth.hashers import make_password
from datetime import datetime, timedelta
from payapp.models import Customer
from django.utils import timezone

from django.utils.timezone import now
import uuid

# Create your models here.
class PlotOnwners(models.Model):
    ownerID = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    owner_name = models.CharField(max_length=100, null=False)
    owner_email = models.CharField(max_length=100,null=False, unique=True)
    owner_phone = models.CharField(max_length=15, unique=True, null=False)
    owner_address = models.TextField(null=True)
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



class ParkingCharge(models.Model):
    pricing_id =  models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    owner_id = models.ForeignKey(PlotOnwners, on_delete=models.CASCADE,related_name='pricing')
    vehicle_type = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    hourly_rate = models.FloatField()
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta :
        db_table = "ParkingCharge"
    
    def __str__(self):
        return f"Station: {self.owner_id.owner_name}, Vehicle Type: {self.vehicle_type.name}"


class ParkingPlots(models.Model):
    plot_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    owner_id = models.ForeignKey(PlotOnwners, on_delete=models.CASCADE,related_name="plots")
    plot_no = models.CharField(max_length=10, unique=True, editable=False)
    status = models.CharField(max_length=20)
    created_at = models.DateTimeField(default=datetime.now) 

    def save(self, *args, **kwargs):
        # Automatically generate plot number if not provided
        if not self.plot_no:
            self.plot_no = f"PLT-{uuid.uuid4().hex[:6].upper()}"
        super(ParkingPlots, self).save(*args, **kwargs)

    def __str__(self):
        return f"Plot No : {self.plot_no}, status {self.status}Owner :{self.owner_id.owner_name}"



class ParkingReservation(models.Model):
    reservation_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user_id = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='reservations')
    plot_id = models.ForeignKey(ParkingPlots, on_delete=models.CASCADE, related_name='reservations')
    start_time = models.DateTimeField(null=False)
    end_time = models.DateTimeField(null=False)
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('reserved', 'Reserved'),
        ('cancelled', 'Cancelled'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='reserved')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Reservation {self.reservation_id} - {self.status}"


class Payment(models.Model):
    _id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='payments')
    reservation_id = models.ForeignKey(ParkingReservation, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=20, choices=[
        ('razorpay', 'Razorpay'),
        ('cash', 'Cash')],
    )
    status = models.CharField(max_length=20,choices=[
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded')],
        default='pending',
    )
    payment_date = models.DateTimeField(auto_now_add=True)
    transaction_id = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(default=timezone.now)



    def __str__(self):
        return f"Payment {self.payment_id} for Reservation {self.reservation_id}"


class Review(models.Model):
    review_id = models.AutoField(primary_key=True)  
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='reviews')  
    reservation = models.ForeignKey(ParkingReservation, on_delete=models.CASCADE, related_name='reviews')
    review_text = models.TextField() 
    rating = models.PositiveSmallIntegerField()
    review_date = models.DateTimeField(auto_now_add=True) 

    def __str__(self):
        return f"Review {self.review_id} by User {self.user_id}"

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(rating__gte=1) & models.Q(rating__lte=5),
                name='rating_between_1_and_5'
            )
        ]