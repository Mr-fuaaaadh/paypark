import jwt
import logging
import random
from .serializers import *
from partnerapp.models import *
from partnerapp.serializers import *
from django.conf import settings
from rest_framework import status
from django.core.mail import send_mail
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from rest_framework.exceptions import APIException
from django.template.loader import render_to_string
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import check_password


logger = logging.getLogger(__name__)


class UserRegisterView(APIView):
    def post(self, request):
        try:
            serializer = UserSerilzer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"success": True,"data": serializer.data,},status=status.HTTP_201_CREATED,)
            return Response({"success": False,"errors": serializer.errors},status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:
            return Response({"success": False,"errors": e.message_dict},status=status.HTTP_400_BAD_REQUEST)
        except APIException as e:
            return Response({"success": False,"errors": str(e)},status=e.status_code)
        except Exception as e:
            return Response({"success": False,"errors": str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class UserLoginAPIView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            customer = Customer.objects.filter(email=email).first()

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
            return None, self._unauthorized_response({"message":"No token provided"})

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = self._get_user_from_payload(payload)
            print(user.pk)
            if not user:
                return None, self._not_found_response({"message":"User not found"})
            
            return user.pk, None
        except jwt.ExpiredSignatureError:
            return None, self._unauthorized_response({"message":"Token has expired"})
        except jwt.InvalidTokenError:
            return None, self._unauthorized_response({"message":"Invalid token"})
        except Exception as e:
            return None, self._server_error_response("An error occurred while decoding the token", str(e))

    def _get_token_from_header(self, auth_header):
        """Extract the token from the Authorization header without the 'Bearer' prefix."""
        if not auth_header:
            return None
        return auth_header.strip() 


    def _get_user_from_payload(self, payload):
        """Retrieve the user from the payload data."""
        user_id = payload.get('id')
        print(user_id)
        if not user_id:
            return None
        return Customer.objects.filter(pk=user_id).first()

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
        print(user)
        if error_response:
            return error_response
        return user
    
    def _get_user_by_email(self, email):
        """Fetch user by email or raise an exception if not found."""
        try:
            return Customer.objects.get(email=email)
        except Customer.DoesNotExist:
            raise ObjectDoesNotExist(f"User with email {email} not found.")
        
    def _bad_request(self, message):
        """Returns a standardized bad request response."""
        return Response({"message": message}, status=status.HTTP_400_BAD_REQUEST)

    


       
        

class UserProfileEdit(BaseTokenView):

    def get(self, request):
        try:
            user = self.authenticate(request)
            serializer = UserSerilzer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
    
        except Exception as e:
            return None, self._server_error_response({"message": "An unexpected error occurred", "error": str(e)})

    def put(self, request):
        try:
            user = self.authenticate(request)
            serializer = UserSerilzer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"data": serializer.data},status=status.HTTP_200_OK)
            return self._bad_request({"message":serializer.errors})
        except Exception as e:
            return self._server_error_response({"message":"An unexpected error occurred","error" : str(e)})
        


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
            return self._server_error_response({"message":f"Error sending email","error": f"{str(e)}"})

    
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

    


class UserPasswordResetOtpVerification(UserForgotPassword):
    def post(self, request):
        user_otp = request.data.get('user_otp')
        user_email = request.data.get('user_email')

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
            return self._server_error_response({"message":"An error occurred while verifying the OTP.","error": f"{str(e)}"})

        return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)

    def _verify_otp(self, user, otp):
        """Verify OTP for the user."""
        otp_record = OTP.objects.filter(user=user, otp=otp).first()
        if not otp_record:
            return False
    
        return True


class ChangePasswordView(UserForgotPassword):
    def put(self, request):
        try:
            # Extract data from the request
            email = request.data.get('email')
            new_passwd = request.data.get('new_passwd')
            re_passwd = request.data.get('re_passwd')


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
            user = self.authenticate(request)
            if not user:
                return self._unauthorized_response({"message":"Authentication failed"})

            # Extract passwords from the request data
            current_passwd = request.data.get('current_passwd')
            new_passwd = request.data.get('new_passwd')
            re_passwd = request.data.get('re_passwd')


            # Check current password
            if not check_password(current_passwd, user.password):
                return self._bad_request({"message":"Current password is incorrect"})

            # Check new password match
            if new_passwd != re_passwd:
                return self._bad_request({"message":"New passwords do not match"})

            # Update password
            user.password = make_password(new_passwd)
            user.save()

            return Response({"status": "success"}, status=status.HTTP_200_OK)

        except ValueError as ve:
            return self._bad_request({"message": str(ve)})

        except AttributeError as ae:
            return self._bad_request({"message": str(ae)})

        except Exception as e:
            return self._server_error_response(message = "An unexpected error occurred" , error = str(e))



class CustomerGetAllVehiclesType(BaseTokenView):
    def get(self, request):
        try:
            vehicle_type = Vehicle.objects.all()
            serializer = VehicleManagementSerializer(vehicle_type, many=True)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return self._server_error_response(message = "An unexpected error occurred" , error = str(e))

class GetAllParkStations(BaseTokenView):
    def get(self,request):
        try :
            stations = PlotOnwners.objects.all()
            serializer = ParkingStationSerializers(stations, many=True)
            return Response({"message":"success","data":serializer.data},status=status.HTTP_200_OK)
        except Exception as e :
            return self._server_error_response(message = "An unexpected error occurred" , error = str(e))



class CustomerParkingPlotReservation(BaseTokenView):

    def post(self, request):
        try:
            serializer = CustomerParkingPlotReservationSerializers(data=request.data)
            if serializer.is_valid():
                # Add custom validation logic if necessary
                serializer.save()
                return Response({"success": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
            return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as ve:
            return Response({"success": False, "errors": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(
                {"success": False, "message": "An unexpected error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self,request):
        try:
            user = self.get_user_from_token(request)
            print(user)
            user_reservations = ParkingReservation.objects.filter(user_id=user)
            serializer = CustomerParkingPlotReservationSerializers(user_reservations, many=True)
            return Response({"message": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"success": False, "message": "An unexpected error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )





