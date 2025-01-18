from rest_framework import serializers
from .models import *
from partnerapp.models import *
from partnerapp.serializers import *



class UserSerilzer(serializers.ModelSerializer):
    class Meta :
        model = Customer 
        fields = "__all__"


class ParkingStationSerializers(serializers.ModelSerializer):
    images = ParkingStationImages(read_only=True, many=True)
    class Meta :
        model = PlotOnwners
        fields = ['ownerID','owner_name','owner_email','owner_phone','latitude','longitude','images']


