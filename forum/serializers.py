from rest_framework import serializers
from .models import Question, Answer, Vote


class AnswerViewSerializer(serializers.ModelSerializer):
    answers_user_id = serializers.ReadOnlyField(source ='user.id')
    answers_user_username = serializers.ReadOnlyField(source ='user.username')
    answers_user_avatar = serializers.ImageField(source='user.user_profile.avatar', read_only=True)
    owner = serializers.SerializerMethodField()
    votes_count = serializers.SerializerMethodField()
    voted = serializers.SerializerMethodField()
    
    
    class Meta:
        model = Answer
        fields = ('id', 'answers_user_id','answers_user_username','answers_user_avatar','answer', 'votes_count','voted', 'owner', 'created_at', 'updated_at')
     
    def get_owner(self, obj):
        request = self.context.get('request')
        if request and request.user == obj.user:
            return True
        return False
    
    def get_votes_count(self, obj):
        return obj.votes.count()
    
    def get_voted(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.votes.filter(user=request.user).exists()
        return False
    
class QuestionSerializer(serializers.ModelSerializer):
    question_user_id = serializers.ReadOnlyField(source ='user.id')
    question_user_username = serializers.ReadOnlyField(source ='user.username')
    question_user_avatar = serializers.ImageField(source='user.user_profile.avatar', read_only=True)
    answers_count = serializers.SerializerMethodField()
    answers = AnswerViewSerializer(many=True, read_only=True)
    owner = serializers.SerializerMethodField()

    class Meta:
        model = Question
        fields = ('id', 'question_user_id','question_user_username','question_user_avatar', 'owner', 'question', 'topic', 'description', 'answers_count', 'answers', 'created_at', 'updated_at')
        read_only_fields = ('id', 'user', 'created_at', 'updated_at')
         

    def get_answers_count(self, obj):
        return obj.answers.count()

    def get_owner(self, obj):
        request = self.context.get('request')
        if request and request.user == obj.user:
            return True 
        return False

class AnswerSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    question = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Answer
        fields = ('id', 'user', 'question', 'answer', 'created_at', 'updated_at')
        read_only_fields = ('id', 'user', 'question', 'created_at', 'updated_at')

