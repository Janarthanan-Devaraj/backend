from rest_framework import serializers
from .models import Note, UpVote

class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ['id', 'title', 'content', 'created_at', 'updated_at', 'author', 'voted']

class NoteSerializer(serializers.ModelSerializer):
    votes_count =serializers.SerializerMethodField()
    voted = serializers.SerializerMethodField()
    owner = serializers.SerializerMethodField()
   
    class Meta:
        model = Note
        fields = ('id', 'user', 'semester', 'Subject', 'note', 'unit', 'votes', 'topic', 'description', 'votes_count', 'voted', 'owner')
        read_only_fields = ('id', 'user', 'votes')
    
    def get_votes_count(self, obj):
        return obj.votes.count()
    
    def get_owner(self, obj):
        request = self.context.get('request')
        if request and request.user == obj.user:
            return True
        return False

class UpVoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = UpVote
        fields = ('id', 'user', 'note', 'created_at')
        read_only_fields = ('id', 'user', 'created_at')
