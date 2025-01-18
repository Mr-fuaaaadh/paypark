from rest_framework import serializers
from .models import *

class ParkOwnerSerializers(serializers.ModelSerializer):
    class Meta :
        model = PlotOnwners
        fields = "__all__"

class VehicleManagementSerializer(serializers.ModelSerializer):
    class Meta :
        model = Vehicle
        fields = "__all__"

class ParkingStationImages(serializers.ModelSerializer):
    class Meta :
        model = Images
        fields = "__all__"