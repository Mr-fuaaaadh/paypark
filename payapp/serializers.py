from rest_framework import serializers
from .models import *
from partnerapp.models import *
from partnerapp.serializers import *
from django.db.models import Q
from datetime import datetime


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



class ParkingStationSerializers(serializers.ModelSerializer):
    images = ParkingStationImages(read_only=True, many=True)
    pricing = ParkingChargeSerilizers(read_only=True, many=True)
    plots = AvailablePlotsSerilizets(read_only=True, many=True)
    class Meta :
        model = PlotOnwners
        fields = ['ownerID','owner_name','owner_email','owner_phone','owner_address','latitude','longitude','pricing','plots','images']


class CustomerParkingPlotReservationSerializers(serializers.ModelSerializer):
    class Meta:
        model = ParkingReservation
        fields = "__all__"

    def validate(self, data):
        plot_id = data['plot_id']
        start_time = data['start_time']
        end_time = data['end_time']

        if start_time >= end_time:
            raise serializers.ValidationError("Start time must be earlier than end time.")

        # Check for conflicting reservations
        conflicting_reservations = ParkingReservation.objects.filter(
            plot_id=plot_id,
            status__in=['active', 'reserved'],  # Only consider active or reserved statuses
        ).filter(
            Q(start_time__lt=end_time) & Q(end_time__gt=start_time)
        )

        if conflicting_reservations.exists():
            raise serializers.ValidationError("This plot is already reserved during the selected time frame.")

        return data


class PaymentInitiationSerializer(serializers.Serializer):
    reservation_id = serializers.UUIDField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)

    def validate_amount(self, value):
        """
        Ensure the amount is positive.
        """
        if value <= 0:
            raise serializers.ValidationError("Amount must be a positive value.")
        return value

    def validate(self, attrs):
        """
        Perform any cross-field validation if needed.
        """
      
        return attrs