from django.contrib import admin
from .models import (Like, Comment, Post)

admin.site.register((Like, Comment, Post))
