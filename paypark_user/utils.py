
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import random
import requests

def send_notification_to_user(user_id, message):
    """
    Sends a notification to a specific user based on user_id.
    """
    channel_layer = get_channel_layer()
    
    # Send notification to the user's WebSocket group
    async_to_sync(channel_layer.group_send)(
        f"user_{user_id}",  # User-specific group name
        {
            "type": "send_notification",  # This corresponds to a function in your consumer
            "message": message,
            "user_id": user_id,  # Optional: include user_id in the message if needed
        }
    )

def send_notification_to_all(message):
    """
    Sends a notification to all connected users.
    """
    channel_layer = get_channel_layer()
    
    # Send notification to the "notifications" group (for all users)
    async_to_sync(channel_layer.group_send)(
        "notifications",  # Public group for all connected clients
        {
            "type": "send_notification",  # This corresponds to a function in your consumer
            "message": message,
        }
    )






def generate_otp(length=6):
    """Generate a numeric OTP of given length."""
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])


def send_otp_via_fast2sms(mobile_number, otp):
    url = "https://www.fast2sms.com/dev/bulkV2"
    
    querystring = {
        "authorization": "UwgyZfzDWVxcu2HFqrmRp64SnohaXbvsALMOeC95jkIJldE0B7dSy3qnGmcxJk82R6Z1LauHDCKVIfEX",              # 🔑 Replace with your API key
        "sender_id": "DLT_SENDER_ID",                  # ✅ Your DLT-approved sender ID
        "message": "YOUR_MESSAGE_ID",                  # ✅ Your approved message ID
        "variables_values": f"{otp}",                  # The generated OTP
        "route": "dlt",
        "numbers": mobile_number
    }

    headers = {
        "cache-control": "no-cache"
    }

    response = requests.request("GET", url, headers=headers, params=querystring)
    print(response.text)
    return response.json()  # return parsed response if needed


# ✅ Example Usage:
# mobile = "9876543210"
# otp = generate_otp()
# print(f"Generated OTP: {otp}")
# send_otp_via_fast2sms(mobile, otp)
