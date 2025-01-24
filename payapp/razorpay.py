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
        logger.info(f"Razorpay order created successfully: {order['id']}")
        return order
    except Exception as e:
        logger.error(f"Error creating Razorpay order: {str(e)}")
        raise ValidationError("Failed to create Razorpay order. Please try again later.")


def verify_razorpay_signature(params_dict):
    """
    Verifies Razorpay payment signature.
    Args:
        params_dict (dict): Razorpay signature verification parameters.
    """
    try:
        razorpay_client.utility.verify_payment_signature(params_dict)
        logger.info("Payment signature verified successfully.")
    except razorpay.errors.SignatureVerificationError as e:
        logger.error("Payment signature verification failed.")
        raise ValidationError("Invalid payment signature.")


def capture_razorpay_payment(payment_id, amount):
    """
    Captures a Razorpay payment.
    Args:
        payment_id (str): Razorpay payment ID.
        amount (float): Amount to capture in INR.
    """
    try:
        capture_response = razorpay_client.payment.capture(payment_id, int(amount * 100))
        logger.info(f"Payment captured successfully: {payment_id}")
        return capture_response
    except Exception as e:
        logger.error(f"Error capturing Razorpay payment: {str(e)}")
        raise ValidationError("Failed to capture Razorpay payment. Please contact support.")
