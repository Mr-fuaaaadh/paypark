from rest_framework import serializers
from .models import *
from partner_app.models import *
from partner_app.serializers import *
from django.db.models import Q
from datetime import datetime
from django.utils.timezone import localtime

import pytz

class UserSerilzer(serializers.ModelSerializer):
    class Meta :
        model = Customer 
        fields = "__all__"


class ParkingChargeSerilizers(serializers.ModelSerializer):
    vehicle_type = serializers.CharField(source='vehicle_type.name')
    class Meta :
        model = ParkingCharge
        fields = ['id','vehicle_type','hourly_rate']


class AvailablePlotsSerilizets(serializers.ModelSerializer):
    class Meta :
        model = ParkingPlots
        fields = ['id','plot_no','status','created_at']

class ViewReviewSerializres(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.name')
    user_image = serializers.ImageField(source='user.profile_image')
    date = serializers.SerializerMethodField()
    time = serializers.SerializerMethodField()
    class Meta :
        model = Review
        fields = "__all__"
        
    def get_date(self, obj):
        # Extracts the date from start_time
        return obj.review_date.date() if obj.review_date else None
    
    def get_time(self, obj):
        # Convert start_time to Kerala Time (IST) and format with AM/PM
        if obj.review_date:
            review_date_kerala = obj.review_date.astimezone(pytz.timezone('Asia/Kolkata'))
            return review_date_kerala.strftime('%I:%M %p')  # Time in 12-hour format with AM/PM
        return None

    

class ParkingStationSerializers(serializers.ModelSerializer):
    images = ParkingStationImages(read_only=True, many=True)
    pricing = ParkingChargeSerilizers(read_only=True, many=True)
    plots = AvailablePlotsSerilizets(read_only=True, many=True)
    reviews = ViewReviewSerializres(read_only=True, many=True)
    
    class Meta :
        model = PlotOnwners
        fields = ['ownerID','owner_name','owner_email','owner_phone','owner_address','latitude','longitude','pricing','plots','images','reviews']


# class CustomerParkingPlotReservationSerializers(serializers.ModelSerializer):

#     class Meta:
#         model = ParkingReservationPayment
#         fields = "__all__"  # or specify the exact fields if needed

#     def validate(self, data):
#         plot_id = data['plot_id']
#         start_time = data['start_time']
#         end_time = data['end_time']
#         current_time = timezone.now()  # Get the current time in the timezone-aware format

#         # Ensure that the start_time is in the future
#         if start_time <= current_time:
#             raise serializers.ValidationError("Start time must be in the future.")

#         # Ensure that the start_time is before the end_time
#         if start_time >= end_time:
#             raise serializers.ValidationError("Start time must be earlier than end time.")

#         # Check for conflicting reservations
#         conflicting_reservations = ParkingReservation.objects.filter(
#             plot_id=plot_id,
#             status__in=['active', 'reserved'],  # Only consider active or reserved statuses
#         ).filter(
#             Q(start_time__lt=end_time) & Q(end_time__gt=start_time)
#         )

#         if conflicting_reservations.exists():
#             raise serializers.ValidationError("This plot is already reserved during the selected time frame.")

#         return data



class CustomerBookdPlots(serializers.ModelSerializer):
    customer = serializers.CharField(source="user.name")
    station = serializers.CharField(source="plot.owner_id.owner_name")
    station_id = serializers.CharField(source="plot.owner_id.ownerID")
    No = serializers.CharField(source="plot.plot_no")

    start_time = serializers.SerializerMethodField()
    end_time = serializers.SerializerMethodField()
    start_date = serializers.SerializerMethodField()
    end_date = serializers.SerializerMethodField()

    class Meta:
        model = ParkingReservationPayment
        fields = "__all__"

    def get_start_time(self, obj):
        return obj.start_time.strftime("%I:%M %p") if obj.start_time else None

    def get_end_time(self, obj):
        return obj.end_time.strftime("%I:%M %p") if obj.end_time else None

    def get_start_date(self, obj):
        return obj.start_time.strftime("%Y-%m-%d") if obj.start_time else None

    def get_end_date(self, obj):
        return obj.end_time.strftime("%Y-%m-%d") if obj.end_time else None


class PaymentSerilizers(serializers.ModelSerializer):
    payment_date = serializers.SerializerMethodField()
    payment_time = serializers.SerializerMethodField()

    class Meta:
        model = ParkingReservationPayment
        fields = ['id','amount','payment_method','payment_status','order_id','reservation_status','payment_date','payment_time']

    def get_payment_date(self, obj):
        # Convert payment_date to Kerala time and extract the date
        indian_timezone = pytz.timezone("Asia/Kolkata")
        local_time = localtime(obj.created_at, indian_timezone)
        return local_time.date()

    def get_payment_time(self, obj):
        # Convert payment_date to Kerala time and extract the time
        indian_timezone = pytz.timezone("Asia/Kolkata")
        local_time = localtime(obj.created_at, indian_timezone)
        return local_time.strftime("%I:%M %p") 
    
    
    
class ReviewSerializres(serializers.ModelSerializer):
    class Meta :
        model = Review
        fields = "__all__" 
    
    
class CusomerPaymentDetails(serializers.ModelSerializer):
    payments = PaymentSerilizers(read_only=True, many=True) 
    class Meta :
        model = Customer
        fields = ['_id','name','email','phone_number','vehicle_number','model_number','profile_image','created_at','payments']
    
        
        
        
class PaymentInitiationSerializer(serializers.Serializer):
    plot_id = serializers.IntegerField(required=True)
    start_time = serializers.DateTimeField(required=True)
    end_time = serializers.DateTimeField(required=True)
    amount = serializers.DecimalField(required=True, max_digits=10, decimal_places=2)

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be a positive value.")
        return value

    def validate(self, attrs):
        plot_id = attrs.get('plot_id')
        start_time = attrs.get('start_time')
        end_time = attrs.get('end_time')

        # ✅ Plot existence check
        try:
            plot = ParkingPlots.objects.get(id=plot_id)
        except ParkingPlots.DoesNotExist:
            raise serializers.ValidationError("Selected parking plot does not exist.")

        # ⏱️ Time validation
        if start_time < timezone.now():
            raise serializers.ValidationError("Start time must be in the future.")
        if end_time <= start_time:
            raise serializers.ValidationError("End time must be after start time.")

        # ⏳ Max booking window
        max_duration = timedelta(hours=24)
        if end_time - start_time > max_duration:
            raise serializers.ValidationError("Booking duration cannot exceed 24 hours.")

        # 🚫 Conflict check
        conflict_exists = ParkingReservationPayment.objects.filter(
            plot_id=plot_id,
            payment_status='completed',
            start_time__lt=end_time,
            end_time__gt=start_time
        ).exists()

        if conflict_exists:
            raise serializers.ValidationError("This time slot is already booked for the selected plot.")

        return attrs

    

class ReviewSerializres(serializers.ModelSerializer):
    class Meta :
        model = Review
        fields = "__all__" 