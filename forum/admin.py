from django.contrib import admin

from . models import (Question, Answer, Vote)

admin.site.register((Question, Answer, Vote))
