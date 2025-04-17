# routing.py
from django.urls import re_path
from . import consumers  # Import the consumer from your application

websocket_urlpatterns = [
    re_path(r'ws/notifications/', consumers.NotificationConsumer.as_asgi()),  # Correct the path if necessary
]
