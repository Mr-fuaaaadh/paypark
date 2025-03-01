import jwt
import random
import logging
from .models import *
from django.conf import settings
from rest_framework import status
from django.core.mail import send_mail
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from django.shortcuts import get_object_or_404
from django.core.validators import validate_email
from django.template.loader import render_to_string
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError, ObjectDoesNotExist



logger = logging.getLogger(__name__)


class BaseDataView(APIView):

    def get_user_from_token(self, request):
        token = self._get_token_from_header(request.headers.get('Authorization'))
        if not token:
            logger.info("No token provided in request header")
            return None, self._unauthorized_response({"message": "No token provided"})

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = self._get_user_from_payload(payload)
            if not user:
                return None, self._not_found_response({"message": "User not found"})
            
            return user, None
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None, self._unauthorized_response({"message": "Token has expired"})
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None, self._unauthorized_response({"message": "Invalid token"})
        except Exception as e:
            logger.exception("Error occurred while decoding the token")
            return None, self._server_error_response("An error occurred while decoding the token", str(e))

    def _get_token_from_header(self, auth_header):
        """Extract the token from the Authorization header (assuming no 'Bearer ' prefix)."""
        if not auth_header:
            return None
        return auth_header.strip()

    def _get_user_from_payload(self, payload):
        """Retrieve the user from the payload data."""
        user_id = payload.get('id')
        logger.debug(f"Decoded user_id from payload: {user_id}")

        if not user_id:
            return None
        
        user = get_object_or_404(PlotOnwners, ownerID=user_id)
        logger.debug(f"Found user: {user}")
        return user

    
    def _admin_authenticate(self, request):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response
        return user

    def _unauthorized_response(self, message):
        """Return a standardized unauthorized response."""
        return Response({"status": "Unauthorized", "message": message}, status=status.HTTP_401_UNAUTHORIZED)

    def _success_response(self, message):
        """Return a standardized Success  response."""
        return Response({"status":"success", "message":message}, status=status.HTTP_200_OK)
    
    def _bad_request(self, message):
        """Returns a standardized bad request response."""
        return Response({"message": message}, status=status.HTTP_400_BAD_REQUEST)
    
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
            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get_user_by_email(self, email):
        """Fetch user by email or raise an exception if not found."""
        try:
            return PlotOnwners.objects.get(owner_email=email)
        except Customer.DoesNotExist:
            raise ObjectDoesNotExist(f"User with email {email} not found.")

    def _generate_otp(self):
        """Generate a 6-digit OTP."""
        return random.randint(100000, 999999)

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

    


    


class ParkOwnersRegistration(BaseDataView):
    def post(self,request):
        try :
            plot_owner = ParkOwnerSerializers(data=request.data)
            if plot_owner.is_valid():
                plot_owner.save()
                return self._success_response({"message":"Owner Register Sucessfully complted"})
            return self._bad_request({"messag":plot_owner.errors})
        except Exception as e :
            return self._server_error_response({"message": "An unexpected error occurred", "error": f"{str(e)}"})

        
class ParOwnerLogin(BaseDataView):
    def post(self, request):
        try:
            # Retrieve credentials from the request
            owner_phone = request.data.get('owner_phone')
            owner_pass = request.data.get('owner_pass')
            print(f"Owner Phone: {owner_phone}, Owner Password: {owner_pass}")

            # Query the database for the user
            park_owner = PlotOnwners.objects.filter(owner_phone=owner_phone).first()
            if not park_owner:
                return self._not_found_response({"message": "User not found"})

            # Verify password
            if not check_password(owner_pass, park_owner.password):
                return Response({"message": "Invalid phone or password"}, status=status.HTTP_401_UNAUTHORIZED)

            # Generate JWT token
            expiration_time = datetime.utcnow() + timedelta(minutes=getattr(settings, 'JWT_EXPIRATION_MINUTES', 60))
            user_token = {
                'id': str(park_owner.ownerID),  # Convert UUID to string
                'phone': park_owner.owner_phone,
                'name': park_owner.owner_name,
                'exp': expiration_time,
                'iat': datetime.utcnow()
            }
            token = jwt.encode(user_token, settings.SECRET_KEY, algorithm='HS256')

            # Return success response with the token
            return Response({
                "status": "success",
                "token": token,
                "name": park_owner.owner_name,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class AdminOrPlotOwnerForgotPasswordView(BaseDataView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return self._bad_request({"message": "Email is required."})

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return self._bad_request({"message": "Invalid email format."})

        try:
            # Retrieve user by email
            user = self._get_user_by_email(email)
        except ObjectDoesNotExist:
            return self._not_found_response({"message": "User not found."})

        # Generate and save OTP
        otp = self._generate_otp()
        self._create_or_update_otp(user, otp)

        try:
            # Send OTP to user's email
            self._send_otp_email(email, otp)
            return Response({"message": "OTP sent successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            return self._server_error_response(
                message="An unexpected error occurred. Please try again later.",
                error=str(e)
            )


    def _create_or_update_otp(self, user, otp):
        """
        Create or update the OTP for the user in the database.
        Prevents multiple OTP records for the same user.
        """
        try:
            AdminOTP.objects.update_or_create(user=user, defaults={'otp': otp})
        except Exception as e:
            logger.error(f"Failed to create or update OTP for user {user}: {str(e)}")
            raise e



class AdminPasswordResetOTPVerification(BaseDataView):
    def post(self, request):
        _otp = request.data.get('_otp')
        email = request.data.get('_email')

        # Validate input data
        if not all([email, _otp]):
            return self._bad_request({"message":"Both user email and OTP are required."})

        try:
            # Fetch user by email
            user = self._get_user_by_email(email)
        except ObjectDoesNotExist:
            logger.warning(f"User with email {email} not found.")
            return self._not_found_response({"message":"User with the provided email does not exist."})
        
        try:
            # Verify OTP
            if not self._verify_otp(user,_otp):
                return self._bad_request({"message":"Invalid or Incorrect OTP."})
                
        except Exception as e:
            return self._server_error_response(
                message="An unexpected error occurred. Please try again later.",
                error=str(e)
            )

        return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)

    def _verify_otp(self, user, otp):
        """Verify OTP for the user."""
        otp_record = AdminOTP.objects.filter(user=user, otp=otp).first()
        if not otp_record:
            return False
    
        return True

class AdminChangePasswordView(BaseDataView):
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
            return self._server_error_response(message="An unexpected error occurred. Please try again later.",error=str(e))

class AdminOrPlotOwnerPasswordReset(BaseDataView):
    def put(self, request):
        try:
            user = self._admin_authenticate(request)
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
            return self._server_error_response(message="An unexpected error occurred. Please try again later.",error=str(e))



class AdminOrProfileOwnerDetailsView(BaseDataView):

    def get(self, request):
        try:
            user = self._admin_authenticate(request)
            serializer = ParkOwnerSerializers(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
    
        except Exception as e:
            return None, self._server_error_response({"message": "An unexpected error occurred", "error": str(e)})

    def put(self, request):
        try:
            user = self._admin_authenticate(request)
            serializer = ParkOwnerSerializers(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"data": serializer.data},status=status.HTTP_200_OK)
            return self._bad_request({"message":serializer.errors})
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred. Please try again later.",error=str(e))

class VehicleManagementView(BaseDataView):

    def post(self, request):
        """Create a new vehicle."""
        try:
            user = self._admin_authenticate(request)
            serializer = VehicleManagementSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()  
                return Response({"message": "Vehicle created successfully."}, status=status.HTTP_201_CREATED)
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred. Please try again later.",error=str(e))

    def get(self, request):
        """Fetch all vehicles."""
        try:
            user = self._admin_authenticate(request)
            vehicles = Vehicle.objects.all()  
            serializer = VehicleManagementSerializer(vehicles, many=True)
            return Response({"message": "Vehicles fetched successfully.", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred. Please try again later.",error=str(e))

    def put(self, request, pk):
        """Update an existing vehicle."""
        try:
            user = self._admin_authenticate(request)
            vehicle = self._get_vehicle(pk)
            serializer = VehicleManagementSerializer(vehicle, data=request.data)
            if serializer.is_valid():
                serializer.save()  # Update vehicle record
                return Response({"message": "Vehicle updated successfully."}, status=status.HTTP_200_OK)
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Vehicle.DoesNotExist:
            return Response({"message": "Vehicle not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred. Please try again later.",error=str(e))

    def patch(self, request, pk):
        """Partially update an existing vehicle."""
        try:
            user = self._admin_authenticate(request)
            vehicle = self._get_vehicle(pk)
            serializer = VehicleManagementSerializer(vehicle, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()  # Apply partial updates
                return Response({"message": "Vehicle updated successfully."}, status=status.HTTP_200_OK)
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Vehicle.DoesNotExist:
            return Response({"message": "Vehicle not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred. Please try again later.",error=str(e))

    def delete(self, request, pk):
        """Delete an existing vehicle."""
        try:
            user = self._admin_authenticate(request)
            vehicle = self._get_vehicle(pk)
            vehicle.delete()  # Perform deletion
            return Response({"message": "Vehicle deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        
        except Vehicle.DoesNotExist:
            return Response({"message": "Vehicle not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred. Please try again later.",error=str(e))

    def _get_vehicle(self, pk):
        """Helper function to retrieve a vehicle instance."""
        return get_object_or_404(Vehicle,pk=pk)



class ManageParkingStationImages(BaseDataView):
    def post(self, request):
        try:
            user = self._admin_authenticate(request)
            auth_user = get_object_or_404(PlotOnwners, pk=user.pk)
            images = request.FILES.getlist('images')
            
            if not images:
                return self._bad_request(message="Please select images")
            
            for image in images:
                image_instance = Images.objects.create(station=auth_user, image=image)

            return self._success_response(message="Images uploaded successfully")
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred", error=str(e))

    def get(self, request):
        try:
            user = self._admin_authenticate(request)
            images = Images.objects.filter(station=user.pk)  
            if not images.exists():
                return self._success_response(message="No images found")
            serialized_images = ParkingStationImages(images, many=True)
            return Response({"message":"success","data":serialized_images.data},status=status.HTTP_200_OK)
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred", error=str(e))
    
    def delete(self,request,pk):
        try :
            user = self._admin_authenticate(request)
            image = get_object_or_404(Images, pk=pk)
            image.delete()
            return self._success_response(message = "Image delete successful")
            
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred", error=str(e))

class VehiclePriceManagmentView(BaseDataView):
    def post(self, request):
        try :
            user = self._admin_authenticate(request)
            request.data['owner_id'] = user.pk
            serializer = VehiclePricingManagementSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return self._success_response(message="Vehicle Price Chargig succesflly completed")
            return self._bad_request({"message":serializer.errors})
        except Exception as e :
            return self._server_error_response(message="An unexpected error occurred", error=str(e))
    
    def get(self,request):
        try :
            user = self._admin_authenticate(request)
            charges = ParkingCharge.objects.filter(owner_id=user.pk)
            serializer = VehiclePricingManagementSerializer(charges, many=True)
            return Response({"status":"success","data":serializer.data},status=status.HTTP_200_OK)
        except Exception as e :
            return self._server_error_response(message="An unexpected error occurred", error=str(e))

    def put(self, request, pk):
        try:
            user = self._admin_authenticate(request)
            
            # Retrieve the ParkingCharge instance by pk
            price = get_object_or_404(ParkingCharge, pk=pk)
            
            # Serialize the incoming data with partial update
            serializer = VehiclePricingManagementSerializer(price, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return self._success_response(message="Vehicle pricing successfully updated")
            return self._bad_request(message="Validation failed", errors=serializer.errors)
        
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred", error=str(e))

    def delete(self,request,pk):
        try :
            user = self._admin_authenticate(request)
            price = get_object_or_404(ParkingCharge, pk=pk)
            price.delete()
            return self._success_response(message="Vehicle pricing successfully deleted")
        except Exception as e:
            return self._server_error_response(message="An unexpected error occurred", error=str(e))



class ParkingPlotManagementView(BaseDataView):
    def post(self,request):
        try :
            user = self._admin_authenticate(request)
            request.data['owner_id']=user.pk
            serializer = ParkingPlotsSerializrs(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return self._success_response(message="Plot succesfully addedd")
            return self._bad_request(message=serializer.errors)
        except Exception as e :
            return self._server_error_response(message="An unexpected error occurred", error=str(e))

    def get(self,request):
        try :
            user = self._admin_authenticate(request)
            owner_plots = ParkingPlots.objects.filter(owner_id=user.pk)
            serializer  = ParkingPlotsSerializrs(owner_plots, many=True)
            return Response({"status":"success","data":serializer.data},status=status.HTTP_200_OK)
        except Exception as e :
            return self._server_error_response(message="An unexpected error occurred", error=str(e))
    
    def put(self,request,pk):
        try :
            user = self._admin_authenticate(request)
            plotID = get_object_or_404(ParkingPlots, pk=pk)
            request.data['owner_id'] =user.pk
            serializer =  ParkingPlotsSerializrs(plotID,data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return self._success_response(message="Plot updated successfuly")
            return self._bad_request(message=serializer.errors)

        except Exception as e :
            return self._server_error_response(message="An unexpected error occurred", error=str(e))
        
    def delete(self, request, pk):
        try:
            user = self._admin_authenticate(request)
            plotID = get_object_or_404(ParkingPlots, pk=pk)
            plotID.delete()
            return self._success_response(message="Plot delete successfuly")
        except Exception as e :
            return self._server_error_response(message="An unexpected error occurred", error=str(e))
 
                    
class AdmiViewAllParkingStations(BaseDataView):
    def get(self,request):
        try :
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            parking_stations = PlotOnwners.objects.all()
            serializer = ParkOwnerAllDatasFetching(parking_stations, many=True)
            return Response({"data":serializer.data},status=status.HTTP_200_OK)
        except Exception as e :
            return self._server_error_response(message="An unexpected error occurred",error=str(e))
