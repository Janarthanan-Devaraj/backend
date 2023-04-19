from django.urls import path
from .views import (
    QuestionListCreateView,
    QuestionRetrieveUpdateDestroyAPIView,
    CreateAnswerView,
    DeleteAnswerView,
    ToggleVoteView,
)

urlpatterns = [
    path('questions/', QuestionListCreateView.as_view(), name='question-list'),
    path('questions/<int:pk>/', QuestionRetrieveUpdateDestroyAPIView.as_view(), name='question-detail'),
    path('questions/<int:question_id>/answers/create/', CreateAnswerView.as_view(), name='answer-create'),
    path('questions/<int:question_id>/answers/<int:answer_id>/delete/', DeleteAnswerView.as_view(), name='answer-delete'),
    path('questions/<int:question_id>/answers/<int:answer_id>/vote/', ToggleVoteView.as_view(), name='answer-vote'),
]