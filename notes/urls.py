from rest_framework.routers import DefaultRouter
from .views import NoteViewSet, UpVoteToggleView
from django.urls import path, include

router = DefaultRouter(trailing_slash=False)

router.register("notes", NoteViewSet)

urlpatterns = [
    path("", include(router.urls)),
    path("notes/<int:pk>/upvote", UpVoteToggleView.as_view()),
]

# append URLs generated by the router to urlpatterns
urlpatterns += router.urls