from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import UserProfile, AcademicInfo, CompanyInfo
from rest_framework import status, permissions, generics, mixins
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    student = serializers.BooleanField(required=True)
    alumni = serializers.BooleanField(required=True)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)

    default_error_messages = {
        'username': 'The username should only contain alphanumeric characters'}

    class Meta:
        model = User
        fields = ['email', 'username', 'password', "student", "alumni"]

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        student = attrs.get('student', '')
        alumni = attrs.get('alumni', '')


        if not username.isalnum():
            raise serializers.ValidationError(
                self.default_error_messages)
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class CustomUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)
    student = serializers.BooleanField(required=True)
    alumni = serializers.BooleanField(required=True)

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            student=validated_data['student'],
            alumni=validated_data['alumni']
        )
        user.set_password(validated_data.get('password'))
        user.save()
        return user

    class Meta:
        model = User
        fields = ('username','email', 'student', 'alumni', 'password')
        extra_kwargs={
            'password':{'write_only':True}
        }

class UserProfileSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only = True)
    
    class Meta:
        model = UserProfile
        fields = '__all__'
    
    def get_user(self, obj):
        user_obj = obj.user
        return CustomUserSerializer(user_obj).data
        
class AcademicInfoSerializer(serializers.ModelSerializer):
    user_data = UserProfileSerializer(read_only = True)
    user = serializers.SerializerMethodField()
    
    class Meta:
        model = AcademicInfo
        fields = "__all__"
        
    def get_user(self, obj):
        user_obj = obj.user
        return CustomUserSerializer(user_obj).data

class CompanyInfoSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    user_data = UserProfileSerializer(read_only = True)
    academic_data = AcademicInfoSerializer(read_only = True)
    
    class Meta:
        model = CompanyInfo
        fields = "__all__"
    
    def get_user(self, obj):
        user_obj = obj.user
        return CustomUserSerializer(user_obj).data


class UserProfileDetailsSerializer(serializers.ModelSerializer):
    user_profile = UserProfileSerializer()
    academic_model = AcademicInfoSerializer(source='student_model')
    company_model = CompanyInfoSerializer(source='alumni_model')

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'student', 'alumni', 'user_profile', 'academic_model', 'company_model')
    


class ChangePasswordSerializer(serializers.Serializer):
    model = User
    
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    
    
class LoginAPISerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(
        max_length=255, min_length=3, read_only=True)

    tokens = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']
        
        
    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }
        
    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        
        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }

        return super().validate(attrs)


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2, required=True)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)
    
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')