from django.urls import path
from .views import *

urlpatterns = [
    path('user/register/',UserRegisterView.as_view()),
    path('user/verify/otp/',VerifyOTPView.as_view()),
    path('user/login/',UserLoginAPIView.as_view()),
    path('user/edit/profile/',UserProfileEdit.as_view()),

    path('user/password/forgot/request/',UserForgotPassword.as_view()),
    path('user/verification/otp/',UserPasswordResetOtpVerification.as_view()),
    path('user/change/password/',ChangePasswordView.as_view()),

    path('user/reset/password/',UserPasswordReset.as_view()),

    path('user/vehicles/',CustomerGetAllVehiclesType.as_view()),
    path('user/parking/stations/',GetAllParkStations.as_view()),

    path('user/parking/reservation/',CustomerParkingPlotReservation.as_view()),
    path('user/parking/reservation/<str:id>/cancel/',CustomerCancelReservation.as_view()),

    path('api/check/plot/availability/', CheckPlotAvailability.as_view(), name='check-plot-availability'),

    path("api/payment/initiate/", RazorpayPaymentInitiation.as_view(), name="razorpay_payment_initiation"),
    path("api/payment/verify/", RazorpayPaymentVerification.as_view(), name="razorpay_payment_verification"),
    
    path('api/parkig/station/review/',CreateReviewInCompletedReservation.as_view())








    
]