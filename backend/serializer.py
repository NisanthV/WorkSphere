from pydoc import describe

from rest_framework.serializers import ModelSerializer
from rest_framework.response import Response
from rest_framework import status
from .models import *


class RoleSerializer(ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'
        extra_kwargs = {
            "organization":{"required":False}
        }

class UserSerializer(ModelSerializer):
    role = RoleSerializer(read_only=True)
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'password','role','organization']
        extra_kwargs = {
            'password': {'write_only': True},
            'role':{"required":False},
            'organization': {"required": False}
        }

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        instance = self.Meta.model(**validated_data)

        if password:
            instance.set_password(password)
            instance.save()
            return instance

        return None

class OrganizationSerializer(ModelSerializer):
    # role = RoleSerializer()
    class Meta:
        model = Organization
        fields = '__all__'
        extra_kwargs = {
            "created_by":{
                "required":False
            }
        }

    def create(self, validated_data):

        validated_data['created_by'] = self.context['request'].user
        print(validated_data)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance



class JobSerializer(ModelSerializer):
    organization = OrganizationSerializer(read_only=True)
    class Meta:
        model = Job
        fields = '__all__'
        extra_kwargs = {
            "organization": {"required": False}
        }
class ApplicationSerializer(ModelSerializer):
    user = UserSerializer(read_only=True)
    job = JobSerializer(read_only=True)

    class Meta:
        model = Application
        fields = '__all__'
        extra_kwargs = {
            "job":{"required":False},
            "user":{"required":False}
        }

    def create(self, validated_data):

        validated_data['job'] = self.context['job']
        validated_data['user'] = self.context['user']

        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance

class NewsSerializer(ModelSerializer):

    class Meta:
        model = News
        fields = '__all__'
        extra_kwargs={
            "created_by":{"required":False},
            "organization":{"required":False}
        }

class ProductSerializer(ModelSerializer):

    class Meta:
        model = Product
        fields = '__all__'
        extra_kwargs={
            "organization":{"required":False}
        }