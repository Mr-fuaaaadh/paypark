from django.contrib import admin
from .models import * 
# Register your models here.


admin.site.register(PlotOnwners)
admin.site.register(Images)
admin.site.register(AdminOTP)
admin.site.register(ParkingPlots)
admin.site.register(Vehicle)
admin.site.register(ParkingCharge)
admin.site.register(ParkingReservationPayment)

