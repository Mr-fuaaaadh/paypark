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

    path('admin/vehicle/',VehicleManagementView.as_view()),
    path('admin/vehicle/<int:pk>/edit/',VehicleManagementView.as_view()),

    path('admin/parking/station/images/',ManageParkingStationImages.as_view()),
    path('admin/parking/station/<int:pk>/images/',ManageParkingStationImages.as_view()),


    path('admin/parking/vehicle/pricig/management/', VehiclePriceManagmentView.as_view()),
    path('admin/parking/vehicle/pricig/<int:pk>/management/', VehiclePriceManagmentView.as_view()),













]