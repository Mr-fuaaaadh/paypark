from rest_framework import serializers
from .models import *
from partnerapp.models import *
from partnerapp.serializers import *



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
    class Meta :
        model = ParkingReservation
        fields = "__all__"