from django.db import models
from django.contrib.auth import get_user_model
from accounts.models import DateAbstract

User = get_user_model()

class Vote(DateAbstract):
    user = models.ForeignKey(User, related_name="userAnswer_likes", on_delete=models.CASCADE)
    answer = models.ForeignKey("Answer", related_name="answer_votes", on_delete=models.CASCADE)

class Answer(DateAbstract):
    user = models.ForeignKey(User, related_name="user_answer", on_delete=models.CASCADE)
    question = models.ForeignKey("Question", on_delete=models.CASCADE, related_name='answer_set')
    answer = models.TextField()
    votes = models.ManyToManyField(Vote, related_name="votes_answer", blank=True)

class Question(DateAbstract):
    user = models.ForeignKey(User, related_name="user_question", on_delete=models.CASCADE)
    question = models.CharField(max_length=200)
    topic = models.CharField(max_length=200)
    description = models.TextField(null=True, blank=True)
    answers = models.ManyToManyField(Answer, related_name="answer_question", blank=True)
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.topic} + {self.user.username} + {self.question}"
