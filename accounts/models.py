from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
from django.core.mail import EmailMultiAlternatives
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.exceptions import ValidationError
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email,password=None, student=False, alumni=False, **extra_fields):
        if username is None:
            raise TypeError('Users should have a username')
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)

        user = self.model(username = username, email=email, student=student, alumni=alumni, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class DateAbstract(models.Model):
    
    created_at = models.DateTimeField(auto_now_add= True)
    updated_at = models.DateTimeField(auto_now= True)
    
    class Meta:
        abstract = True


class CustomUser(AbstractBaseUser, DateAbstract):
    username = models.CharField(max_length=100, unique=True, db_index=True)
    email = models.EmailField(verbose_name='email', max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    student = models.BooleanField(default=False)
    alumni = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_online = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()
    
    
    def clean(self):
        # Check if the username is already taken
        if CustomUser.objects.filter(username=self.username).exists():
            raise ValidationError({'username': 'This username is already taken.'})

        # Check if the email is already taken
        if CustomUser.objects.filter(email=self.email).exists():
            raise ValidationError({'email': 'This email is already taken.'})

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh) ,
            'access': str(refresh.access_token) ,
        }
    class Meta:
        ordering = ("created_at",)

class UserProfile(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name='user_profile', on_delete= models.CASCADE)
    avatar = models.ImageField(upload_to="user_avatar", blank=True, null=True, default='https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460__340.png')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=6, choices=(("male", "male"), ("female", "female")))
    dob = models.DateField()
    
    def __str__(self):
        return self.user.email
    
    class Meta:
        ordering = ("created_at",)
    
class AcademicInfo(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="student_model", on_delete= models.CASCADE)
    roll_number = models.CharField(max_length=7, unique=True)
    degree = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    current_semester = models.PositiveSmallIntegerField(null=True, blank=True)
    cgpa = models.FloatField(max_length=3)

    
    def __str__(self):
        return self.user.email
    
    def clean(self):
        # Check if the username is already taken
        if AcademicInfo.objects.filter(username=self.roll_number).exists():
            raise ValidationError({'roll_number': 'This roll number has already registered.'})
    

class CompanyInfo(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="alumni_model", on_delete= models.CASCADE)
    company_name = models.CharField(max_length=200)
    role = models.CharField(max_length=100)
    location = models.CharField( max_length=20)
    
    def __str__(self):
        return self.user.email
    

class ClubInfo(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="club_model", on_delete= models.CASCADE)
    club_name = models.TextField()


class Favorite(models.Model):
    user = models.OneToOneField(CustomUser, related_name="user_favorite", on_delete=models.CASCADE)
    favorite = models.ManyToManyField(CustomUser, related_name="user_favoured")
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} + {self.favorite.username}"
    
    class Meta:
        ordering = ("created_at",)   

