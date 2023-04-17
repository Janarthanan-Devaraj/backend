from django.db import models
from django.contrib.auth import get_user_model
from accounts.models import DateAbstract
User = get_user_model()

class Like(DateAbstract):
    user = models.ForeignKey(User, related_name="user_likes", on_delete=models.CASCADE)
    post = models.ForeignKey("Post", related_name="post_likes", on_delete=models.CASCADE)
    
class Comment(DateAbstract):
    user = models.ForeignKey(User, related_name="user_comments", on_delete=models.CASCADE)
    post = models.ForeignKey("Post", related_name="post_comments", on_delete=models.CASCADE)
    comment = models.TextField()

class Post(DateAbstract):
    user = models.ForeignKey(User, related_name="user_posts", on_delete=models.CASCADE)
    image = models.ImageField(upload_to='posts', blank=True, null=True)
    title = models.TextField(null=True, blank= True)
    body = models.TextField(null=True, blank= True)
    likes = models.ManyToManyField(Like, related_name="liked_posts", blank= True)
    comments = models.ManyToManyField(Comment, related_name="commented_posts", blank= True)
    
    def __str__(self):
        return f"{self.user.username} - {self.title}"

