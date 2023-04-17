from rest_framework import serializers
from .models import Post, Comment

class CommentViewSerializer(serializers.ModelSerializer):
    comments_user_id = serializers.ReadOnlyField(source ='user.id')
    comments_username = serializers.ReadOnlyField(source ='user.username')
    comments_avatar = serializers.ImageField(source='user.user_profile.avatar', read_only=True)
    owner = serializers.SerializerMethodField()

    class Meta:
        model = Comment
        fields = ('id','comments_user_id', 'comments_username', 'comments_avatar', 'comment', 'owner', 'created_at', 'updated_at')
    
    def get_owner(self, obj):
        request = self.context.get('request')
        if request and request.user == obj.user:
            return True
        return False

class PostSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source='user.username')
    likes_count = serializers.SerializerMethodField()
    comments_count = serializers.SerializerMethodField()
    comments = CommentViewSerializer(many=True, read_only=True)
    owner = serializers.SerializerMethodField()
    liked = serializers.SerializerMethodField()
    
    class Meta:
        model = Post
        fields = ('id', 'user', 'image','title', 'body', 'likes_count', 'comments_count','comments', 'liked', 'owner', 'created_at','updated_at')
        

    def get_likes_count(self, obj):
        return obj.likes.count()
    
    def get_comments_count(self, obj):
        return obj.comments.count()

    def get_owner(self, obj):
        request = self.context.get('request')
        if request and request.user == obj.user:
            return True
        return False
    
    def get_liked(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.likes.filter(user=request.user).exists()
        return False

    
class CommentSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    post = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Comment
        fields = ('id', 'user', 'post', 'comment', 'created_at', 'updated_at')
        read_only_fields = ('id', 'user', 'post', 'created_at', 'updated_at')
