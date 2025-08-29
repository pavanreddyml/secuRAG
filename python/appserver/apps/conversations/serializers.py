# serializers.py
from rest_framework import serializers
from .models import Conversation, Message

class ConversationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Conversation
        fields = ('id', 'conversation_title', 'created_at', 'updated_at')

class MessageSerializer(serializers.ModelSerializer):
    conversation = serializers.UUIDField(source='conversation_id', read_only=True)
    content = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = ('id', 'conversation', 'content', 'role', 'order', 'created_at', 'updated_at')
        read_only_fields = ('order', 'created_at', 'updated_at')

    def get_content(self, obj: Message):
        # user => original content; non-user => transformed content (fallback to original)
        if obj.role == 'user':
            return obj.content
        return obj.transformed_content if obj.transformed_content is not None else obj.content

class StartConversationSerializer(serializers.Serializer):
    messageContent = serializers.CharField()

class ContinueConversationSerializer(serializers.Serializer):
    conversationId = serializers.UUIDField()
    messageContent = serializers.CharField()

class ConversationMessagesQuerySerializer(serializers.Serializer):
    from_order = serializers.IntegerField(required=False)
    limit = serializers.IntegerField(required=False, min_value=1, max_value=200, default=20)

class ConversationWithMessagesSerializer(serializers.Serializer):
    conversation = ConversationSerializer()
    messages = MessageSerializer(many=True)
    next_from_order = serializers.IntegerField(allow_null=True)

class ConversationListQuerySerializer(serializers.Serializer):
    from_updated_at = serializers.DateTimeField(required=False)
    limit = serializers.IntegerField(required=False, min_value=1, max_value=200, default=20)

class ConversationListResponseSerializer(serializers.Serializer):
    conversations = ConversationSerializer(many=True)
    next_from_updated_at = serializers.DateTimeField(allow_null=True)
