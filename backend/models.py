from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.files.storage import FileSystemStorage
from django.db.models import Model


class User(AbstractUser):
    username = None
    name = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=108,null=False)
    organization = models.ForeignKey('Organization',on_delete=models.SET_NULL,null=True)
    role = models.ForeignKey('Role', on_delete=models.SET_NULL, null=True, blank=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.name

class Organization(models.Model):

    name = models.CharField(max_length=30)
    description = models.CharField(max_length=100)
    created_by = models.ForeignKey('User',on_delete=models.CASCADE,related_name='organization_creater')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Role(models.Model):

    name = models.CharField(max_length=20)
    description = models.CharField(max_length=25)
    organization = models.ForeignKey('Organization',on_delete=models.CASCADE)
    create_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class News(models.Model):
    title = models.CharField(max_length=30,null=True)
    content = models.TextField()
    organization = models.ForeignKey('Organization',on_delete=models.CASCADE)
    created_by = models.ForeignKey('User',on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class Job(models.Model):
    title = models.CharField(max_length=30,null=True)
    content = models.TextField()
    role = models.CharField(max_length=20,null=True)
    organization = models.ForeignKey('Organization',on_delete=models.CASCADE,null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class Application(models.Model):

    job = models.ForeignKey('Job',on_delete=models.CASCADE)
    user = models.ForeignKey('User',on_delete=models.CASCADE)
    applied_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.job.title


class Product (models.Model):

    title = models.CharField(max_length=20)
    content = models.TextField()
    organization = models.ForeignKey('Organization',on_delete=models.CASCADE)
    path = models.ImageField(upload_to='products/%Y/%m/',blank=True,null=True)
    added = models.DateTimeField(auto_now_add=True)

