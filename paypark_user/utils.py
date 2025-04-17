
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

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