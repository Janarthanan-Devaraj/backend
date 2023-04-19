from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from .models import Question, Answer, Vote
from .serializers import QuestionSerializer, AnswerSerializer
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework import status
from rest_framework import permissions
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from django.db.models import Count
from rest_framework.generics import CreateAPIView, DestroyAPIView


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit or delete it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD, or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the object.
        return obj.user == request.user

class QuestionListCreateView(ListCreateAPIView):
    serializer_class = QuestionSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def get_queryset(self):
        queryset = Question.objects.all()
        queryset = super().get_queryset()
        queryset = queryset.annotate(answers_count=Count('answers', distinct=True))
        return queryset

class QuestionRetrieveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView):
    queryset = Question.objects.all()
    serializer_class = QuestionSerializer
    permission_classes = [IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]
    

class CreateAnswerView(CreateAPIView):
    queryset = Answer.objects.all()
    serializer_class = AnswerSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def post(self, request, question_id):
        question = get_object_or_404(Question, id=question_id)
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user, question=question)
            question.answers.add(serializer.instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)# <-- pass status as a keyword argument


class DeleteAnswerView(DestroyAPIView):
    queryset = Answer.objects.all()
    serializer_class = AnswerSerializer
    permission_classes = [IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]

    def delete(self, request, question_id, answer_id):
        answer = get_object_or_404(Answer, id=answer_id, user=request.user)
        
        if answer.user != request.user:
            return Response({'error': 'You do not have permission to delete this comment.'}, status=status.HTTP_403_FORBIDDEN)
        
        answer.delete()
        return Response({'status': 'Answer deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)

    
    
class ToggleVoteView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]

    def post(self, request, question_id, answer_id):
        answer = get_object_or_404(Answer, id=answer_id, question_id=question_id)
        user_vote = answer.votes.filter(user=request.user).first()

        try:
            if user_vote:
                # user has already voted, so delete the vote
                user_vote.delete()
                return Response({'status': 'unvoted'}, status=status.HTTP_200_OK)
            else:
                # user has not voted yet, so add a new vote
                vote = Vote.objects.create(user=request.user, answer=answer)
                answer.votes.add(vote)
                return Response({'status': 'voted'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
