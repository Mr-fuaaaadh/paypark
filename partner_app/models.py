from django.db import models
from django.contrib.auth.hashers import make_password
from datetime import datetime, timedelta
from django.utils import timezone  # Import timezone
from paypark_user.models import Customer
from django.utils import timezone

from django.utils.timezone import now
import uuid

# Create your models here.
class PlotOnwners(models.Model):
    ownerID = models.UUIDField(default=uuid.uuid4, editable=False, unique=True,db_index=True)
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
        default='operator',
        db_index=True
    )
    is_active = models.BooleanField(default =True,db_index=True)
    created_at = models.DateTimeField(auto_now_add=True,db_index=True)

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
    created_at = models.DateTimeField(default=timezone.now) 

    def save(self, *args, **kwargs):
        # Automatically generate plot number if not provided
        if not self.plot_no:
            self.plot_no = f"PLT-{uuid.uuid4().hex[:6].upper()}"
        super(ParkingPlots, self).save(*args, **kwargs)

    def __str__(self):
        return f"Plot No : {self.plot_no}, status {self.status}Owner :{self.owner_id.owner_name}"



class Review(models.Model):
    review_id = models.AutoField(primary_key=True)  
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='reviews')  
    owner  = models.ForeignKey(PlotOnwners, on_delete=models.CASCADE, related_name='reviews')
    review_text = models.TextField() 
    rating = models.FloatField()
    review_date = models.DateTimeField(auto_now_add=True) 

    def __str__(self):
        return f"Review {self.owner.owner_name} by User {self.user.name}"

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(rating__gte=1) & models.Q(rating__lte=5),
                name='rating_between_1_and_5'
            )
        ]
        


class ParkingReservationPayment(models.Model):
    """
    A combined model that tracks both the reservation details (slot, time, user)
    and the payment details (amount, method, status, transaction IDs) in one place.
    """
    
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded')]
    
    RESERVATION_STATUS_CHOICES = [
        ('reserved', 'Reserved'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    PAYMENT_METHOD_CHOICES = [
        ('razorpay', 'Razorpay'),
        ('cash', 'Cash'),]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='payments')
    plot = models.ForeignKey(ParkingPlots, on_delete=models.CASCADE, related_name='reservations')
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()


    reservation_status = models.CharField(max_length=10,choices=RESERVATION_STATUS_CHOICES,default='reserved')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    order_id = models.CharField(max_length=100, blank=True, null=True, help_text="Razorpay order_id or any external gateway order ID")
    payment_id = models.CharField(max_length=100, blank=True, null=True, unique=True, help_text="Razorpay payment_id or any external gateway payment ID")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"ReservationPayment {self.user.name} -  {self.payment_status}"

    def mark_payment_completed(self, razorpay_payment_id=None):
        """
        Utility to update payment status to 'completed' once you verify success.
        Optionally pass in the payment_id from Razorpay or another provider.
        """
        self.payment_status = 'completed'
        if razorpay_payment_id:
            self.payment_id = razorpay_payment_id
        if self.reservation_status == 'reserved':
            self.reservation_status = 'active'
        self.save()