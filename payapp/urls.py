from django.urls import path
from .views import *
urlpatterns = [
    path('user/register/',UserRegisterView.as_view()),
    path('user/login/',UserLoginAPIView.as_view()),
    path('user/edit/profile/',UserProfileEdit.as_view()),

    path('user/password/forgot/request/',UserForgotPassword.as_view()),
    path('user/verification/otp/',UserPasswordResetOtpVerification.as_view()),
    path('user/change/password/',ChangePasswordView.as_view()),

    path('user/reset/password/',UserPasswordReset.as_view()),


    path('user/vehicles/',CustomerGetAllVehiclesType.as_view()),
    path('user/parking/stations/',GetAllParkStations.as_view()),

    path('user/parking/reservation/',CustomerParkingPlotReservation.as_view()),








    
]