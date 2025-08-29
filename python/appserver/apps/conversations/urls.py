from django.urls import path
from .views import (
    start_conversation,
    continue_conversation,
    get_conversation_messages,
    list_conversations,
    fetch_audit_logs,
    delete_audit_logs,
    delete_conversation,
)

urlpatterns = [
    path("conversations/start/", start_conversation, name="start_conversation"),
    path("conversations/<uuid:conversation_id>/next/", continue_conversation, name="continue_conversation"),
    path("conversations/<uuid:conversation_id>/messages/", get_conversation_messages, name="get_conversation_messages"),
    path("conversations/<uuid:conversation_id>/delete/", delete_conversation, name="delete_conversation"),
    path("conversations/list/", list_conversations, name="list_conversations"),

    # ---- Audit log endpoints (proxy to Flask) ----
    path("audit/<str:message_id>/", fetch_audit_logs, name="fetch_audit_logs"),
    path("audit/<str:message_id>/delete/", delete_audit_logs, name="delete_audit_logs"),
]
