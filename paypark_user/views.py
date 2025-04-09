import jwt
import logging
import random
import razorpay
from .serializers import *
from partner_app.models import *
from partner_app.serializers import *
from django.conf import settings
from rest_framework import status
from django.db import transaction
from django.core.mail import send_mail
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from rest_framework.exceptions import APIException
from django.template.loader import render_to_string
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.http import Http404
from celery import shared_task
from .razorpay import *
from django.core.cache import cache
import time
from django.db import DatabaseError
from rest_framework.pagination import PageNumberPagination
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.generics import ListAPIView
from django.db.models import Prefetch
from django.db import connection
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
logger = logging.getLogger(__name__)






class UserLoginAPIView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            
            customer = Customer.objects.filter(email=email, is_active=True).first()

            if customer and check_password(password, customer.password):
                # Generate JWT token
                expiration_time = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
                user_token = {
                    'id': customer.pk,
                    'email': customer.email,
                    'name': customer.name,
                    'exp': expiration_time,
                    'iat': datetime.utcnow() 
                }
                token = jwt.encode(user_token, settings.SECRET_KEY, algorithm='HS256')
                response = Response({ "status": "success",
                    "token": token,
                    'name': customer.name,
                }, status=status.HTTP_200_OK)
                return response
            else:
                return Response({"message": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class BaseTokenView(APIView):

    def get_user_from_token(self, request):
        token = self._get_token_from_header(request.headers.get('Authorization'))
        if not token:
            return None, self._unauthorized_response("No token provided")

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = self._get_user_from_payload(payload)
            if not user:
                return None, self._not_found_response("User not found")

            return user.pk, None
        except jwt.ExpiredSignatureError:
            return None, self._unauthorized_response("Token has expired")
        except jwt.InvalidTokenError:
            return None, self._unauthorized_response("Invalid token")
        except Exception as e:
            return None, self._server_error_response("An error occurred while decoding the token", str(e))

    def _get_token_from_header(self, auth_header):
        """Extract the token from the Authorization header."""
        return auth_header.strip() if auth_header else None

    def _get_user_from_payload(self, payload):
        """Retrieve the user from the payload data."""
        user_id = payload.get('id')
        return Customer.objects.filter(pk=user_id).first() if user_id else None

    def _unauthorized_response(self, message):
        """Return a standardized unauthorized response."""
        return Response({"status": "Unauthorized", "message": message}, status=status.HTTP_401_UNAUTHORIZED)

    def _not_found_response(self, message):
        """Return a standardized not found response."""
        return Response({"message": message}, status=status.HTTP_404_NOT_FOUND)

    def _server_error_response(self, message, error):
        """Return a standardized server error response."""
        return Response(
            {"status": "error", "message": message, "error": error},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    def authenticate(self, request):
        user, error_response = self.get_user_from_token(request)
        return error_response or user

    def _get_user_by_email(self, email):
        """Fetch user by email or raise an exception if not found."""
        user = Customer.objects.filter(email=email).first()
        if user:
            return user
        raise ObjectDoesNotExist(f"User with email {email} not found.")
    
    def _bad_request(self, message):
        """Returns a standardized bad request response."""
        return Response({"message": message}, status=status.HTTP_400_BAD_REQUEST)

    def _send_notificatio_using_email(self, email, message):
        """Your Parking Slot Reservation is Complete"""
        email_body = render_to_string('success.html', {'message': message})
        send_mail(
            'Pay to Park Slot Reservation',
            '',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
            html_message=email_body
        )

    def _generate_otp(self):
        """Generate a 6-digit OTP."""
        return random.randint(100000, 999999)

    def _create_or_update_otp(self, user, otp):
        """Create or update the OTP for the user."""
        OTP.objects.update_or_create(user=user, defaults={'otp': otp})
    
    def _send_otp_email(self, email, otp):
        """Send OTP email to the user."""
        email_body = render_to_string('otp.html', {'otp': otp})
        send_mail(
            'Pay to Park Password Reset OTP',
            '',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
            html_message=email_body
        )




class UserRegisterView(BaseTokenView):
    def post(self, request):
        try:
            email = request.data.get("email")

            # Check if email is already registered
            if Customer.objects.filter(email=email).exists():
                return Response({"success": False, "error": "User already exists"}, status=status.HTTP_400_BAD_REQUEST)

            otp = self._generate_otp()

            cache.set(f"otp_{email}", otp, timeout=300)

            self._send_otp_email(email, otp)

            return Response({"success": True, "message": "OTP sent to email"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"success": False, "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class VerifyOTPView(APIView):
    def post(self, request):
        try:
            email = request.data.get("email")
            otp = request.data.get("otp")

            # Retrieve OTP from cache
            stored_otp = cache.get(f"otp_{email}")

            if not stored_otp:
                return Response({"success": False, "error": "OTP expired or invalid"}, status=status.HTTP_400_BAD_REQUEST)
             
            if str(stored_otp) != str(otp):
                return Response({"success": False, "error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

            # Remove OTP from cache after verification
            cache.delete(f"otp_{email}")

            # Save user data
            serializer = UserSerilzer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"success": True, "message": "User registered successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)

            return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except ValidationError as e:
            return Response({"success": False, "errors": e.message_dict}, status=status.HTTP_400_BAD_REQUEST)
        except APIException as e:
            return Response({"success": False, "errors": str(e)}, status=e.status_code)
        except Exception as e:
            return Response({"success": False, "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    
class CustomerParkingPlotReservationPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

       
        

class UserProfileEdit(BaseTokenView):

    def get(self, request):
        """Retrieve user profile details."""
        try:
            user_id, _ = self.get_user_from_token(request) 
            customer = get_object_or_404(Customer, pk=user_id)

            cache_key = f"user_profile_{user_id}"
            customer_data = cache.get(cache_key)

            if not customer_data:
                serializer = CusomerPaymentDetails(customer)
                customer_data = serializer.data
                cache.set(cache_key, customer_data, timeout=60 * 5)  # Cache for 5 minutes

            return Response({"data": customer_data}, status=status.HTTP_200_OK)

        except Exception as e:
            return self._server_error_response(
                message="An unexpected error occurred", error=str(e)
            )

    def put(self, request):
        """Update user profile details."""
        try:
            user_id, _ = self.get_user_from_token(request)
            customer = get_object_or_404(Customer, pk=user_id)

            serializer = UserSerilzer(customer, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                cache.delete(f"user_profile_{user_id}")  # Clear cache after update
                return Response({"data": serializer.data}, status=status.HTTP_200_OK)

            return self._bad_request(message=serializer.errors)

        except Exception as e:
            return self._server_error_response(
                message="An unexpected error occurred", error=str(e)
            )


class UserForgotPassword(BaseTokenView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return self._bad_request({"message":"Email is required."})

        try:
            user = self._get_user_by_email(email)
        except ObjectDoesNotExist:
            return self._not_found_response({"message":"User not found."})

        otp = self._generate_otp()
        self._create_or_update_otp(user, otp)

        try:
            self._send_otp_email(email, otp)
            return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
        except Exception as e:
            return self._server_error_response(message = "Error sending email", error = f"{str(e)}")

    
    

    


class UserPasswordResetOtpVerification(UserForgotPassword):
    def post(self, request):
        user_otp = request.data.get('otp')
        user_email = request.data.get('email')

        # Validate input data
        if not all([user_email, user_otp]):
            return self._bad_request({"message":"Both user email and OTP are required."})

        try:
            # Fetch user by email
            user = self._get_user_by_email(user_email)
        except ObjectDoesNotExist:
            logger.warning(f"User with email {user_email} not found.")
            return self._not_found_response({"message":"User with the provided email does not exist."})
        
        try:
            # Verify OTP
            if not self._verify_otp(user, user_otp):
                return self._bad_request({"message":"Invalid or Incorrect OTP."})
        except Exception as e:
            print(e)
            return self._server_error_response(message = "An error occurred while verifying the OTP.", error =  f"{str(e)}")

        return Response({"message" "OTP verified successfully."}, status=status.HTTP_200_OK)

    def _verify_otp(self, user, otp):
        """Verify OTP for the user."""
        otp_record = OTP.objects.filter(user=user, otp=otp).first()
        if not otp_record:
            return False
        return True


class ChangePasswordView(BaseTokenView):
    def put(self, request):
        try:
            # Extract data from the request
            email = request.data.get('email')
            new_passwd = request.data.get('new_passwd')
            re_passwd = request.data.get('re_passwd')

            print(f"email : {email} new_passwd : {new_passwd} re_passwd : {re_passwd}")


            # Validate input
            if not all([email, new_passwd, re_passwd]):
                return  self._bad_request({"message":"Email, new password, and re-typed password are required."})

            # Check if passwords match
            if new_passwd != re_passwd:
                return self._bad_request({"message":"Passwords do not match."})

            try:
                user = self._get_user_by_email(email)
            except ObjectDoesNotExist:
                return self._not_found_response({"message":"User with the provided email does not exist."})

            user.password = make_password(new_passwd)  
            user.save()

            return Response({"message": "Password updated successfully."},status=status.HTTP_200_OK,)

        except Exception as e:
            return self._server_error_response(message = "An unexpected error occurred" , error = str(e))

            

class UserPasswordReset(UserProfileEdit):
    def put(self, request):
        try:
            user, _ = self.get_user_from_token(request)
            if not user:
                return self._unauthorized_response({"message":"Authentication failed"})
            
            customer = get_object_or_404(Customer,pk=user)

            # Extract passwords from the request data
            current_passwd = request.data.get('current_passwd')
            new_passwd = request.data.get('new_passwd')
            re_passwd = request.data.get('re_passwd')


            # Check current password
            if not check_password(current_passwd, customer.password):
                return self._bad_request(message ="Current password is incorrect")

            # Check new password match
            if new_passwd != re_passwd:
                return self._bad_request(message ="New passwords do not match")

            # Update password
            customer.password = make_password(new_passwd)
            customer.save()

            return Response({"status": "success"}, status=status.HTTP_200_OK)

        except ValueError as ve:
            return self._bad_request(message = str(ve))

        except AttributeError as ae:
            return self._bad_request(message = str(ae))

        except Exception as e:
            return self._server_error_response(message = "An unexpected error occurred" , error = str(e))



class CustomerGetAllVehiclesType(BaseTokenView):
    def get(self, request):
        try:
            cache_key = 'all_vehicle_types'
            # Attempt to retrieve cached data
            cached_data = cache.get(cache_key)
            if cached_data is not None:
                return Response({"message": "success", "data": cached_data},status=status.HTTP_200_OK)

            vehicle_type = Vehicle.objects.all().only('vehicle_type_id')
            serializer = VehicleManagementSerializer(vehicle_type, many=True)
            cache.set(cache_key, serializer.data, timeout=60 * 60)  # Cache for 1 hour
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return self._server_error_response(message = "An unexpected error occurred" , error = str(e))
            

class GetAllParkStations(BaseTokenView):
    def get(self, request):
        try:
            # Optimized Query - Removed `select_related('pricing')` since it's not a ForeignKey
            park_stations = (
                PlotOnwners.objects
                .only('id', 'ownerID', 'owner_name', 'owner_email', 'owner_phone', 'latitude', 'longitude')  
                .prefetch_related('pricing', 'images', 'plots', 'reviews')  # Prefetch ManyToMany/Reverse FK fields
            )

            serializer = ParkingStationSerializers(park_stations, many=True)
            response_data = serializer.data

            return Response({"status": "success", "data": response_data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred", error=str(e))
        

class CustomerParkingPlotReservation(BaseTokenView):
    def get(self, request):
        try:
            user, _ = self.get_user_from_token(request)
            customer = get_object_or_404(Customer, pk=user)

            reservations = ParkingReservationPayment.objects.filter(user=user).select_related('user', 'plot', 'plot__owner_id')


            serializer = CustomerBookdPlots(reservations, many=True)

            return Response(
                {"status": "success", "results": serializer.data},
                status=status.HTTP_200_OK
            )

        except ObjectDoesNotExist:
            return Response(
                {"status": "error", "message": "Customer not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CustomerCancelReservation(BaseTokenView):
    def put(self, request, id):
        try:
            user, _ = self.get_user_from_token(request)
            reserved_plot = get_object_or_404(ParkingReservationPayment, pk=id, user=user)
            
            if reserved_plot.status == 'cancelled':
                return Response({"success": False, "message": "This reservation is already cancelled."}, status=status.HTTP_400_BAD_REQUEST)
            
            reserved_plot.payment_status = 'cancelled'
            reserved_plot.save()  
            serializer = PaymentSerilizers(reserved_plot)
            return Response({"status": "success", "message": "Your reservation has been cancelled successfully."}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"success": False, "message": "An unexpected error occurred", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class RazorpayPaymentInitiation(BaseTokenView):
    """
    API View to initiate Razorpay payments without creating a ParkingReservation upfront.
    """
    def post(self, request):
        # Extract user from token
        user_id, _ = self.get_user_from_token(request)
        if not user_id:
            return Response({"error": "Authentication failed."}, status=status.HTTP_401_UNAUTHORIZED)

        # Validate incoming data
        serializer = PaymentInitiationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Extract validated data
        
        validated_data = serializer.validated_data
        plot_id = validated_data["plot_id"]
        start_time = validated_data["start_time"]  # Already a Python datetime
        end_time = validated_data["end_time"]  
        amount = validated_data["amount"]


        # Validate plot existence
        plot = get_object_or_404(ParkingPlots, pk=plot_id)

        # Create a Razorpay order
        razorpay_order = create_razorpay_order(float(amount))

        # Store payment in "pending" status
        with transaction.atomic():
            ParkingReservationPayment.objects.create(
                user_id=user_id,
                plot=plot,
                amount=amount,
                payment_method="razorpay",
                reservation_status="pending",
                order_id=razorpay_order["id"],
                start_time=start_time,
                end_time=end_time,
            )

        # Return response with Razorpay order details
        return Response({
            "order_id": razorpay_order["id"],
            "amount": str(amount),
            "key": settings.RAZORPAY_API_KEY,
            "callback_url": request.build_absolute_uri("/api/payment/verify/"),
        }, status=status.HTTP_201_CREATED)





class RazorpayPaymentVerification(BaseTokenView):
    """
    API View to verify Razorpay payments.
    """

    def post(self, request):
        try:
            user_id, _ = self.get_user_from_token(request)
            
            try:
                customer = get_object_or_404(Customer,pk=user_id)
            except Http404:
                return Response({"error": "Customer not found."}, status=status.HTTP_404_NOT_FOUND)

            razorpay_order_id = request.data.get("razorpay_order_id")
            razorpay_payment_id = request.data.get("razorpay_payment_id")
            razorpay_signature = request.data.get("razorpay_signature")

            if not razorpay_order_id or not razorpay_payment_id or not razorpay_signature:
                return Response({"error": "Incomplete payment details."}, status=status.HTTP_400_BAD_REQUEST)

            # Enqueue verification and capturing in a background task
            verify_and_capture_payment(razorpay_order_id, razorpay_payment_id, razorpay_signature, customer.pk)

            admins = PlotOnwners.objects.filter(role='admin', is_active=True)
            for admin in admins:
                message = f"New payment verified for customer {customer.name}"
                send_admin_notification(message)

            return Response({"message": "Payment verification initiated."}, status=status.HTTP_202_ACCEPTED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

def send_admin_notification(message):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        'admin_notifications',
        {
            'type': 'send_notification',
            'message': message
        }
    )

def verify_and_capture_payment(razorpay_order_id, razorpay_payment_id, razorpay_signature, customer_id):
    try:
        # Fetch the customer
        customer = Customer.objects.get(pk=customer_id)

        # Verify Razorpay signature
        params_dict = {
            "razorpay_order_id": razorpay_order_id,
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_signature": razorpay_signature,
        }
        verify_razorpay_signature(params_dict)

        # Fetch the payment object
        payment = get_object_or_404(ParkingReservationPayment, order_id=razorpay_order_id, user=customer.pk)

        # Attempt to capture payment
        capture_razorpay_payment(razorpay_payment_id, payment.amount)

        # ✅ Correctly update payment status and save transaction ID
        payment.payment_status = "completed"
        payment.payment_id = razorpay_payment_id  # Assuming you have a field for storing transaction IDs
        payment.save()

        return {"status": "success", "message": "Payment captured successfully", "payment_id": razorpay_payment_id}

    except Exception as e:
        # Ensure payment status is updated to "failed" if it exists
        payment = ParkingReservationPayment.objects.filter(order_id=razorpay_order_id).first()
        if payment:
            payment.payment_status = "failed"
            payment.save()

        raise ValidationError("Payment verification/capture failed. Please try again.")




class CreateReviewInCompletedReservation(BaseTokenView):
    """
    Handles the creation of reviews for completed reservations.
    """

    def post(self, request):
        try:
            user_id, _ = self.get_user_from_token(request)
            customer = get_object_or_404(Customer, pk=user_id)

            owner_id = request.data.get('owner')
            if not owner_id:
                return Response(
                    {"message": "The 'owner' field is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            owner_instance = PlotOnwners.objects.filter(ownerID=owner_id).first()
            if not owner_instance:
                return Response(
                    {"message": "No matching owner found."},
                    status=status.HTTP_404_NOT_FOUND
                )

            request.data['user'] = customer.pk
            request.data['owner'] = owner_instance.pk

            serializer = ReviewSerializres(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {"status": "success", "message": "Review added successfully."},
                    status=status.HTTP_201_CREATED
                )
            return self._bad_request(message=serializer.errors)

        except Customer.DoesNotExist:
            return self._not_found_response(message="Customer not found.")
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred.",error=str(e))
            
        