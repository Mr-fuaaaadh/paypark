# consumers.py

from channels.generic.websocket import AsyncWebsocketConsumer
import json

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_name = 'notifications'  # Can be dynamic for user-specific

        # Join the group
        await self.channel_layer.group_add(self.group_name, self.channel_name)

        # Accept the WebSocket connection
        await self.accept()

    async def disconnect(self, close_code):
        # Leave the group when the WebSocket closes
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        # Handle receiving WebSocket messages from the client
        text_data_json = json.loads(text_data)
        message = text_data_json.get('message')

        # Send message to WebSocket group
        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'send_notification',
                'message': message
            }
        )

    async def send_notification(self, event):
        # Send message to WebSocket client
        message = event['message']
        await self.send(text_data=json.dumps({
            'message': message
        }))
