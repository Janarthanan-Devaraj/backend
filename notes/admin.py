from django.contrib import admin

from .models import (Note, UpVote)

admin.site.register((Note, UpVote))
