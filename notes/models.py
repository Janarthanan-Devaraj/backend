from django.db import models
from django.contrib.auth import get_user_model
from accounts.models import DateAbstract

User = get_user_model()

class UpVote(DateAbstract):
    user = models.ForeignKey(User, related_name="user_upVote", on_delete=models.CASCADE)
    note = models.ForeignKey("Note", related_name="notes_vote", on_delete=models.CASCADE)

class Note(DateAbstract):
    user = models.ForeignKey(User, related_name="user_notes",on_delete=models.CASCADE)
    semester = models.IntegerField()
    Subject = models.CharField(max_length=300)
    note = models.FileField(upload_to="notes", blank=True, null=True)
    unit = models.IntegerField()
    votes = models.ManyToManyField(UpVote, related_name="vote_notes", blank= True)
    topic = models.TextField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    