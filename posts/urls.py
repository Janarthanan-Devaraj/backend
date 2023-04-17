from django.urls import path
from .views import PostListCreateView, PostRetrieveUpdateDestroyView, LikeToggleView, CommentCreateView, CommentDeleteView

urlpatterns = [
    path('post', PostListCreateView.as_view(), name='post-list-create'),
    path('post/<int:pk>', PostRetrieveUpdateDestroyView.as_view(), name='post-retrieve-update-destroy'),
    path('post/<int:pk>/likes', LikeToggleView.as_view(), name='post-like-toggle'),
    path('post/<int:pk>/comments', CommentCreateView.as_view(), name='post-comment-create'),
    path('post/<int:pk>/comments/<int:comment_pk>', CommentDeleteView.as_view(), name='comment-delete'),
]
