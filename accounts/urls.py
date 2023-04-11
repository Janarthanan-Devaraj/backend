from django.urls import path, include

from .views import (SignUpView, LoginView,  VerifyEmail,
                    UserProfileListCreateAPIView, 
                    AcademicInfoListCreateAPIView, 
                    CompanyInfoListCreateAPIView,
                    UserRetrieveView, ChangePasswordView,
                    RegisterView, LoginAPIView, 
                    SetNewPasswordAPIView,
                    RequestPasswordResetEmail, PasswordTokenCheckAPI,)

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)





urlpatterns = [
    path('signup', RegisterView.as_view(),name='signup' ),
#     path('register', SignUpView.as_view(),name='register' ),
    path('email-verify', VerifyEmail.as_view(), name="email-verify"),
    path('signin', LoginAPIView.as_view(), name='signin'),
    path('login', LoginView.as_view(),name='login' ),
    path('profile', UserRetrieveView.as_view(), name='profile'),
    path('changepassword', ChangePasswordView.as_view(), name='changepassword'),
    path('password-reset', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('profile/create', UserProfileListCreateAPIView.as_view(), name = 'profile-create'),
    path('profile/academic', AcademicInfoListCreateAPIView.as_view(), name='academic-info-list-create'),
    path('profile/company', CompanyInfoListCreateAPIView.as_view(), name='company-info-list-create'),
    path('token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email', RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),
    path('password-reset/<uidb64>/<token>',
         PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),
         name='password-reset-complete')
    


]