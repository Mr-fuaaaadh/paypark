from rest_framework import serializers
from .models import *
from partner_app.models import *

class ParkOwnerSerializers(serializers.ModelSerializer):
    class Meta :
        model = PlotOnwners
        exclude = ["password"]

class VehicleManagementSerializer(serializers.ModelSerializer):
    class Meta :
        model = Vehicle
        fields = "__all__"

                   

class ParkingStationImages(serializers.ModelSerializer):
    class Meta:
        model = Images
        fields = "__all__"

    
    
class VehiclePricingManagementSerializer(serializers.ModelSerializer):
    class Meta :
        model = ParkingCharge
        fields = "__all__"

class ParkingPlotsSerializrs(serializers.ModelSerializer):
    class Meta :
        model = ParkingPlots
        fields = "__all__"



        
class AdminAllParkingPlosView(serializers.ModelSerializer):
    class Meta :
        model = ParkingPlots
        fields = "__all__"
        
class PaymentModelSerializers(serializers.ModelSerializer):
    class Meta:
        model = ParkingReservationPayment
        fields = "__all__"
        
class ParkingReservationSerializer(serializers.ModelSerializer):
    reservations = PaymentModelSerializers(read_only=True, many=True)
    customer_name = serializers.CharField(source="user.name", read_only=True)
    station_name = serializers.CharField(source="plot.owner_id.owner_name", read_only=True)

    class Meta:
        model = ParkingReservationPayment
        fields = "__all__"   
        
class ParkOwnerAllDatasFetching(serializers.ModelSerializer):
    images = ParkingStationImages(many=True, read_only=True)
    pricing = VehiclePricingManagementSerializer(read_only=True, many=True)
    plots = ParkingPlotsSerializrs(read_only=True, many=True)
    payments = serializers.SerializerMethodField()


    class Meta:
        model = PlotOnwners
        fields = [
            'id',
            'ownerID',
            'owner_name',
            'owner_email',
            'owner_phone',
            'owner_address',
            'latitude',
            'longitude',
            'account_number',
            'ifsc_code',
            'ownership_type',
            'created_at',
            'images',
            'pricing',
            'plots',
            'payments'
        ]

    def get_payments(self,obj):
        payment  = ParkingReservationPayment.objects.filter(plot = obj.id)
        serializer = PaymentModelSerializers(payment, many=True)
        return serializer.data
        

class ReviewSerializer(serializers.ModelSerializer):
    owner_name = serializers.CharField(source="owner.owner_name")
    class Meta:
        model = Review
        fields = ['owner','owner_name','review_text','rating','review_date']


class ParkingReservationPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = ParkingReservationPayment
        fields = ['id', 'amount', 'payment_method', 'payment_status', 'order_id', 'payment_id', 'created_at']


class CustomerSerializers(serializers.ModelSerializer):
    reviews = ReviewSerializer(read_only=True, many=True)
    payments = ParkingReservationPaymentSerializer(read_only=True, many=True)
    class Meta:
        model = Customer
        fields = ['id','_id', 'name', 'email', 'phone_number', 'profile_image', 'reviews','model_number','vehicle_number','payments','is_active']

