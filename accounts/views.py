from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.shortcuts import redirect

from .serializers import(CustomUserSerializer, User, LoginSerializer, 
                         UserProfile, AcademicInfo, 
                         CompanyInfo, AcademicInfoSerializer,
                         CompanyInfoSerializer, UserProfileSerializer,
                         UserProfileDetailsSerializer, ChangePasswordSerializer,
                         RegisterSerializer, EmailVerificationSerializer,
                         LoginAPISerializer, ResetPasswordEmailRequestSerializer, 
                         SetNewPasswordSerializer, LogoutSerializer)

from rest_framework import status, generics, mixins
from django.utils.encoding import force_bytes
from rest_framework.permissions import IsAuthenticated
from .renderers import UserRenderer
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user)

        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')

        absurl = 'http://localhost:3000/signup/email-verify/'+ str(token)

        email_body = 'Hi '+user.username + ' Use the link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verify your email'}

        Util.send_email(data)
        
        message = {
            'refresh': str(token),
            'access': str(token.access_token),
            'user_data': user_data
        }
        return Response(message, status=status.HTTP_201_CREATED)




# class RegisterView(generics.GenericAPIView):
#     serializer_class = RegisterSerializer

#     def post(self, request):
#         user = request.data
#         serializer = self.serializer_class(data=user)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         user_data = serializer.data
#         user = User.objects.get(email=user_data['email'])
#         token = RefreshToken.for_user(user).access_token
        
#         current_site = get_current_site(request).domain
#         relative_link = reverse('email-verify')

#         absurl = 'http://'+current_site+relative_link+"?token="+str(RefreshToken.for_user(user).access_token)

#         email_body = 'Hi '+user.username + \
#             ' Use the link below to verify your email \n' + absurl
#         data = {'email_body': email_body, 'to_email': user.email,
#                 'email_subject': 'Verify your email'}

#         Util.send_email(data)
        
#         message = {
#             'token' : str(token), 'user_data' : user_data
#         }
#         return Response(message, status=status.HTTP_201_CREATED)

class VerifyEmail(APIView):
    serializer_class = EmailVerificationSerializer
    renderer_classes = (UserRenderer,)

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def post(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            user.delete()
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            user.delete()
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class SignUpView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = (UserRenderer,)

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)

        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        })

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginAPISerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

        
class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get("email")
        password = serializer.data.get("password")

        user = authenticate(request, email=email, password=password)
        if user is None:
            return Response({"error": "Invalid email or password"})

        refresh = RefreshToken.for_user(user)

        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user_id" : user.id
        })

class UserProfileListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = (UserRenderer,)

    def get_queryset(self):
        return UserProfile.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class AcademicInfoListCreateAPIView(generics.ListCreateAPIView):
    queryset = AcademicInfo.objects.all()
    serializer_class = AcademicInfoSerializer
    permission_classes = (IsAuthenticated,)
    renderer_classes = (UserRenderer,)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class CompanyInfoListCreateAPIView(generics.ListCreateAPIView):
    queryset = CompanyInfo.objects.all()
    serializer_class = CompanyInfoSerializer
    permission_classes = (IsAuthenticated,)
    renderer_classes = (UserRenderer,)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class UserRetrieveView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileDetailsSerializer
    renderer_classes = (UserRenderer,)

    def get_object(self):
        return self.request.user

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)
    renderer_classes = (UserRenderer,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relative_link = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'http://localhost:3000'+ relative_link
            email_body = f'Hello,\nUse the link below to reset your password:\n{absurl}\n'
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset your password'}
            Util.send_email(data)

        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            
            return Response({'success': True, 'message' : 'Credentials Valid', 'uidb64' : uidb64,"token" :token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
                    

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)



























# class RequestPasswordResetEmail(generics.GenericAPIView):
#     serializer_class = ResetPasswordEmailRequestSerializer
#     renderer_classes = (UserRenderer,)
    
#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
        
#         email = request.data.get('email', '')

#         if User.objects.filter(email=email).exists():
#             user = User.objects.get(email=email)
#             uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
#             token = PasswordResetTokenGenerator().make_token(user)
#             current_site = get_current_site(
#                 request=request).domain
#             relativeLink = reverse(
#                 'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

#             redirect_url = request.data.get('redirect_url', '')
#             absurl = 'http://'+current_site + relativeLink
#             email_body = 'Hello, \n Use link below to reset your password  \n' + \
#                 absurl+"?redirect_url="+redirect_url
#             data = {'email_body': email_body, 'to_email': user.email,
#                     'email_subject': 'Reset your passsword'}
#             Util.send_email(data)
#         return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


# class PasswordTokenCheckAPI(generics.GenericAPIView):
#     serializer_class = SetNewPasswordSerializer
#     renderer_classes = (UserRenderer,)

#     def get(self, request, uidb64, token):

#         redirect_url = request.GET.get('redirect_url')

#         try:
#             id = smart_str(urlsafe_base64_decode(uidb64))
#             user = User.objects.get(id=id)
            
#             if not PasswordResetTokenGenerator().check_token(user, token):
#                 return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            
#             return Response({'success': True, 'message' : 'Credentials Valid', 'uidb64' : uidb64,"token" :token}, status=status.HTTP_200_OK)

#         except DjangoUnicodeDecodeError as identifier:
#             if not PasswordResetTokenGenerator().check_token(user):
#                 return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
                    


# class SetNewPasswordAPIView(generics.GenericAPIView):
#     serializer_class = SetNewPasswordSerializer
#     renderer_classes = (UserRenderer,)

#     def patch(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    renderer_classes = (UserRenderer,)

    permission_classes = (IsAuthenticated,)

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)





# class UserProfileListAPIView(generics.CreateAPIView):
#     permission_classes = [IsAuthenticated]
#     queryset = UserProfile.objects.all()
#     serializer_class = UserProfileSerializer
#     lookup_field = 'pk'


# class UserProfileAPIView(APIView):

#     def get(self, request, format=None):
#         user_profile = UserProfile.objects.get(user=request.user)
#         serializer = UserProfileSerializer(user_profile)
#         return Response(serializer.data)
    
#     def post(self, request, format=None):
#         user = user.objects.get(user = request.user)
#         request.data['user'] = user
#         serializer = UserProfileSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)