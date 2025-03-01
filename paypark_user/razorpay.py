import razorpay
from django.conf import settings
from rest_framework.exceptions import ValidationError
import logging

logger = logging.getLogger(__name__)

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))


def create_razorpay_order(amount, currency="INR"):
    """
    Creates a Razorpay order.
    Args:
        amount (float): Payment amount in INR.
        currency (str): Payment currency (default: INR).
    Returns:
        dict: Razorpay order details.
    """
    try:
        order = razorpay_client.order.create({
            "amount": int(amount * 100),  # Convert to paise
            "currency": currency,
            "payment_capture": 1,
        })
        return order
    except Exception as e:
        raise ValidationError("Failed to create Razorpay order. Please try again later.")


def verify_razorpay_signature(params_dict):
    """
    Verifies Razorpay payment signature.
    Args:
        params_dict (dict): Razorpay signature verification parameters.
    """
    try:
        razorpay_client.utility.verify_payment_signature(params_dict)
    except razorpay.errors.SignatureVerificationError as e:
        raise ValidationError("Invalid payment signature.")


def capture_razorpay_payment(razorpay_payment_id, amount):
    """
    Captures a Razorpay payment.
    
    Args:
        razorpay_payment_id (str): Razorpay payment ID.
        amount (float): Amount to capture in INR.
    
    Returns:
        dict: Response from Razorpay API.
    """
    try:
        # Fetch payment details to check if it's already captured
        payment_details = razorpay_client.payment.fetch(razorpay_payment_id)

        if payment_details.get("status") == "captured":
            return {"status": "success", "message": "Payment is already captured", "payment_id": razorpay_payment_id}

        # Capture the payment
        capture_response = razorpay_client.payment.capture(razorpay_payment_id, int(amount))
        return capture_response

    except razorpay.errors.BadRequestError as e:
        error_message = str(e)
        if "already been captured" in error_message:
            return {"status": "success", "message": "Payment was already captured", "payment_id": razorpay_payment_id}
        
        raise ValidationError("Failed to capture Razorpay payment. Please contact support.")

    except Exception as e:
        raise ValidationError("Failed to capture Razorpay payment. Please contact support.")
