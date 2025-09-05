# views.py
from datetime import timedelta
from django.utils import timezone
from django.db import transaction
from django.db.models import Max
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from .models import Conversation, Message
from .serializers import (
    ConversationSerializer,
    MessageSerializer,
    StartConversationSerializer,
    ContinueConversationSerializer,
    ConversationMessagesQuerySerializer,
    ConversationWithMessagesSerializer,
    ConversationListQuerySerializer,
    ConversationListResponseSerializer,
)
from django.conf import settings
import requests

def simulate_ai_response(json_body):
    url = settings.SECURAG_SERVER_URL.rstrip("/") + "/api/ai-response"
    response = requests.post(url, json=json_body)
    if response.status_code != 200:
        return None
    return response.json().get("ai_response", "AI response not available")

def simulate_input_transformation(user_input, message_id, write_log):
    json_body = {
        "content": user_input,
        "message_id": str(message_id),
        "write_log": write_log
    }
    url = settings.SECURAG_SERVER_URL.rstrip("/") + "/api/transform-input"
    response = requests.post(url, json=json_body)
    if response.status_code != 200:
        return None
    data = response.json()
    transformed_content = data.get("transformed_content")
    flagged = data.get("flagged", False)
    return transformed_content, flagged

def simulate_output_transformation(ai_response, message_id, write_log):
    json_body = {
        "content": ai_response,
        "message_id": str(message_id),
        "write_log": write_log
    }
    url = settings.SECURAG_SERVER_URL.rstrip("/") + "/api/transform-output"
    response = requests.post(url, json=json_body)
    if response.status_code != 200:
        return None
    data = response.json()
    transformed_content = data.get("transformed_content")
    flagged = data.get("flagged", False)
    return transformed_content, flagged

@api_view(['POST'])
@permission_classes([AllowAny])
def start_conversation(request):
    s = StartConversationSerializer(data=request.data)
    s.is_valid(raise_exception=True)
    content = s.validated_data['messageContent']

    # Atomic 1: create conversation + USER message (role injected here)
    conversation = Conversation.objects.create(conversation_title=content[:64])

    last_order = Message.objects.filter(conversation=conversation).aggregate(m=Max('order'))['m'] or 0
    user_msg = Message.objects.create(
        conversation=conversation,
        content=content,
        role='user',
        order=last_order + 1,
    )

    input_t, input_flagged = simulate_input_transformation(user_msg.content, user_msg.id, settings.RECORD_AUDIT_LOGS)
    print(input_t, input_flagged)
    if input_t is None:
        return Response({"detail": "Input transformation failed."}, status=status.HTTP_400_BAD_REQUEST)

    Message.objects.filter(id=user_msg.id).update(transformed_content=input_t)
    Conversation.objects.filter(id=conversation.id).update(updated_at=timezone.now())

    if input_flagged:
        ai_raw = "Not Generated due to flagged Input"
        ai_out = input_t
    else:
        # Atomic 2: generate AI + ASSISTANT message
        ai_raw = simulate_ai_response({"prompt": input_t})
        if ai_raw is None:
            return Response({"detail": "AI response generation failed."}, status=status.HTTP_400_BAD_REQUEST)

        ai_out, output_flagged = simulate_output_transformation(ai_raw, user_msg.id, settings.RECORD_AUDIT_LOGS)
        if ai_out is None:
            return Response({"detail": "AI output transformation failed."}, status=status.HTTP_400_BAD_REQUEST)

    assistant_msg = Message.objects.create(
        conversation=conversation,
        content=ai_raw,
        transformed_content=ai_out,
        role='assistant',
        order=user_msg.order + 1,
    )
    Conversation.objects.filter(id=conversation.id).update(updated_at=timezone.now())

    return Response(
        {
            "conversation": ConversationSerializer(conversation).data,
            "messages": MessageSerializer([user_msg, assistant_msg], many=True).data,
        },
        status=status.HTTP_201_CREATED,
    )

@api_view(['POST'])
@permission_classes([AllowAny])
def continue_conversation(request, conversation_id):
    s = ContinueConversationSerializer(data={**request.data, "conversationId": str(conversation_id)})
    s.is_valid(raise_exception=True)

    conversation_id = s.validated_data['conversationId']
    content = s.validated_data['messageContent']

    # Atomic 1: add USER message to existing conversation
    try:
        conversation = Conversation.objects.get(id=conversation_id)
    except Conversation.DoesNotExist:
        return Response({"detail": "Conversation not found."}, status=status.HTTP_404_NOT_FOUND)

    last_order = Message.objects.filter(conversation=conversation).aggregate(m=Max('order'))['m'] or 0
    user_msg = Message.objects.create(
        conversation=conversation,
        content=content,
        role='user',
        order=last_order + 1,
    )

    input_t, input_flagged = simulate_input_transformation(user_msg.content, user_msg.id, settings.RECORD_AUDIT_LOGS)
    if input_t is None:
        return Response({"detail": "Input transformation failed."}, status=status.HTTP_400_BAD_REQUEST)

    Message.objects.filter(id=user_msg.id).update(transformed_content=input_t)
    Conversation.objects.filter(id=conversation.id).update(updated_at=timezone.now())

    if input_flagged:
        ai_raw = "Not Generated due to flagged Input"
        ai_out = input_t
    else:
        # Atomic 2: generate AI + ASSISTANT message
        ai_raw = simulate_ai_response({"prompt": input_t})
        if ai_raw is None:
            return Response({"detail": "AI response generation failed."}, status=status.HTTP_400_BAD_REQUEST)

        ai_out, output_flagged = simulate_output_transformation(ai_raw, user_msg.id, settings.RECORD_AUDIT_LOGS)
        if ai_out is None:
            return Response({"detail": "AI output transformation failed."}, status=status.HTTP_400_BAD_REQUEST)

    assistant_msg = Message.objects.create(
        conversation=conversation,
        content=ai_raw,
        transformed_content=ai_out,
        role='assistant',
        order=user_msg.order + 1,
    )
    Conversation.objects.filter(id=conversation.id).update(updated_at=timezone.now())

    return Response(
        {
            "conversation": ConversationSerializer(conversation).data,
            "messages": MessageSerializer([user_msg, assistant_msg], many=True).data,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(['GET'])
@permission_classes([AllowAny])
def get_conversation_messages(request, conversation_id):
    conversation = get_object_or_404(Conversation, id=conversation_id)
    qs = ConversationMessagesQuerySerializer(data=request.query_params)
    qs.is_valid(raise_exception=True)
    limit = qs.validated_data.get('limit', 20)

    provided_from = qs.validated_data.get('from_order')
    if provided_from is None:
        provided_from = Message.objects.filter(conversation=conversation).aggregate(m=Max('order'))['m'] or 0

    base_qs = Message.objects.filter(conversation=conversation, order__lte=provided_from).order_by('-order')[:limit]
    messages_desc = list(base_qs)
    messages = list(reversed(messages_desc))

    if messages:
        min_order = messages[0].order
        has_more = Message.objects.filter(conversation=conversation, order__lt=min_order).exists()
        next_from_order = min_order - 1 if has_more else None
    else:
        next_from_order = None

    payload = {
        "conversation": conversation,
        "messages": messages,
        "next_from_order": next_from_order,
    }
    out = ConversationWithMessagesSerializer(payload).data
    return Response(out, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([AllowAny])
def list_conversations(request):
    qs = ConversationListQuerySerializer(data=request.query_params)
    qs.is_valid(raise_exception=True)
    limit = qs.validated_data.get('limit', 20)

    provided_from = qs.validated_data.get('from_updated_at')
    if provided_from is None:
        provided_from = Conversation.objects.aggregate(m=Max('updated_at'))['m'] or timezone.now()

    base_qs = (
        Conversation.objects
        .filter(updated_at__lte=provided_from)
        .order_by('-updated_at', '-created_at')[:limit]
    )
    conversations = list(base_qs)

    if conversations:
        min_updated_at = conversations[-1].updated_at
        has_more = Conversation.objects.filter(updated_at__lt=min_updated_at).exists()
        next_from_updated_at = (min_updated_at - timedelta(microseconds=1)) if has_more else None
    else:
        next_from_updated_at = None

    payload = {
        "conversations": ConversationSerializer(conversations, many=True).data,
        "next_from_updated_at": next_from_updated_at,
    }
    out = ConversationListResponseSerializer(payload).data
    return Response(out, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_conversation(request, conversation_id):
    conversation = get_object_or_404(Conversation, id=conversation_id)
    with transaction.atomic():
        Message.objects.filter(conversation=conversation).delete()
        conversation.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@permission_classes([AllowAny])
def fetch_audit_logs(request, message_id):
    base_url = settings.SECURAG_SERVER_URL.rstrip("/")
    if not base_url:
        return Response({"detail": "SECURAG_SERVER_URL not configured"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    try:
        url = f"{base_url}/api/audit/{message_id}/"
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        return Response(resp.json(), status=resp.status_code)
    except requests.exceptions.RequestException as e:
        return Response({"detail": f"Audit log server not reachable: {str(e)}"}, status=status.HTTP_502_BAD_GATEWAY)


@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_audit_logs(request, message_id):
    base_url = settings.SECURAG_SERVER_URL.rstrip("/")
    if not base_url:
        return Response({"detail": "SECURAG_SERVER_URL not configured"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    try:
        url = f"{base_url}/api/audit/{message_id}/delete/"
        resp = requests.delete(url, timeout=5)
        resp.raise_for_status()
        return Response(resp.json(), status=resp.status_code)
    except requests.exceptions.RequestException as e:
        return Response({"detail": f"Audit log server not reachable: {str(e)}"}, status=status.HTTP_502_BAD_GATEWAY)