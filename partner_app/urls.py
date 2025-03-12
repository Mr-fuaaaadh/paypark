from django.urls import path
from .views import *


urlpatterns = [
    path('register/',ParkOwnersRegistration.as_view()),
    path('login/',ParOwnerLogin.as_view()),

    path('forgott/password/email/verification/',AdminOrPlotOwnerForgotPasswordView.as_view()),
    path('forgott/password/OTP/verification/',AdminPasswordResetOTPVerification.as_view()),
    path('admin/change/password/',AdminChangePasswordView.as_view()),


    path('admin/reset/password/',AdminOrPlotOwnerPasswordReset.as_view()),
    path('admin/profile/',AdminOrProfileOwnerDetailsView.as_view()),

    path('admin/customers/',AdminAllCustomers.as_view()),


    path('admin/vehicle/',VehicleManagementView.as_view()),
    path('admin/vehicle/<int:pk>/edit/',VehicleManagementView.as_view()),

    path('owner/parking/station/images/',ManageParkingStationImages.as_view()),
    path('owner/parking/station/<int:pk>/images/',ManageParkingStationImages.as_view()),


    path('owner/parking/vehicle/pricig/management/', VehiclePriceManagmentView.as_view()),
    path('owner/parking/vehicle/pricig/<int:pk>/management/', VehiclePriceManagmentView.as_view()),

    path('owner/parking/plots/management/', ParkingPlotManagementView.as_view()),
    path('owner/parking/plots/<int:pk>/management/', ParkingPlotManagementView.as_view()),

    # path('owner/parking/reservations/', ReservationManagementView.as_view()),
    path('admin/parking/stations/', AdmiViewAllParkingStations.as_view()),
    path('admin/parking/reservations/', AllParkingReservations.as_view()),

















]