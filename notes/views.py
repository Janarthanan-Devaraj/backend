from django.shortcuts import render
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from .models import Note, UpVote
from .serializers import NoteSerializer
from rest_framework import permissions
from rest_framework import viewsets, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit or delete it.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the post.
        return obj.user == request.user
    

class NoteViewSet(viewsets.ModelViewSet):
    queryset = Note.objects.all()
    serializer_class = NoteSerializer

    def create(self, request):
        serializer = NoteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpVoteToggleView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly, ]

    def post(self, request, pk):
        note = get_object_or_404(Note, pk=pk)
        user = request.user
        
        try:
            upvote = UpVote.objects.get(user=user, note=note)
            upvote.delete()
            note.up_vote.remove(upvote)
            return Response({'status': 'unvoted'}, status=status.HTTP_200_OK)
        
        except UpVote.DoesNotExist:
            upvote = UpVote(user=user, note=note)
            upvote.save()
            note.up_vote.add(upvote)
            return Response({'status': 'upvoted'}, status=status.HTTP_201_CREATED)