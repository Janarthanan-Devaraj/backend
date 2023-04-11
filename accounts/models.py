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

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

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

class UserProfile(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="user_profile", on_delete= models.CASCADE)
    avatar = models.ImageField(upload_to="user_avatar", blank=True, null=True, default='https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460__340.png')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=6, choices=(("male", "male"), ("female", "female")))
    dob = models.DateField()
    
    def __str__(self):
        return self.user.email
    
class AcademicInfo(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="student_model", on_delete= models.CASCADE)
    roll_number = models.CharField(max_length=7)
    degree = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    current_semester = models.PositiveSmallIntegerField(null=True, blank=True)
    cgpa = models.FloatField(max_length=3)

    
    def __str__(self):
        return self.user.email

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


