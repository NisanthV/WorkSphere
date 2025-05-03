from http.client import responses

from django.views.decorators.csrf import ensure_csrf_cookie
from openai import organization
from rest_framework.decorators import api_view
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import AnonymousUser
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from .serializer import UserSerializer
from django.http import JsonResponse
from rest_framework import status
from .serializer import *
from .models import *
import jwt, datetime
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render


def index(request):

    return render(request, 'index.html')


@ensure_csrf_cookie
def get_csrf_token(reqest):
    return JsonResponse({"data":"token set"})

class JobPagination(PageNumberPagination):
    page_size = 20

@api_view(['POST'])
def role_search(request):
    if isinstance(request.user, AnonymousUser):
        return Response("Login required", status=status.HTTP_403_FORBIDDEN)

    job = Job.objects.filter(role__istartswith=request.data['role'])
    if not job:
        return Response(status=status.HTTP_404_NOT_FOUND)
    paginator = JobPagination()
    result_page = paginator.paginate_queryset(job, request)
    serialized = JobSerializer(result_page, many=True)
    return paginator.get_paginated_response(serialized.data)



@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    data = request.data

    # 1) Make sure they passed an id and it matches the logged-in user
    if user.id != data.get('id'):
        return Response({"detail": "user mismatch"}, status=status.HTTP_403_FORBIDDEN)

    # 2) Pull out and validate the three passwords from the payload
    current = data.get('current_password')
    new_pw  = data.get('new_password')
    confirm = data.get('confirm_password')
    if not all([current, new_pw, confirm]):
        return Response(
            {"detail": "Provide 'current_password', 'new_password' and 'confirm_password'."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # 3) Check the old password
    if not user.check_password(current):
        return Response(
            {"detail": "Current password is incorrect."},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # 4) Confirm the new passwords match
    if new_pw != confirm:
        return Response(
            {"detail": "New passwords do not match."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # 5) All good → set, save, and keep the session alive
    user.set_password(new_pw)
    user.save()
    response = Response(status=status.HTTP_200_OK)
    response.delete_cookie("jwt")
    response.data = "Password changed successfully."
    return response

@api_view(['POST'])
def product_search(request):
    if isinstance(request.user, AnonymousUser):
        return Response("Login required", status=status.HTTP_403_FORBIDDEN)

    instance = Product.objects.filter(title__istartswith=request.data['title'])
    if not instance.exists():
        return Response("product not available", status=status.HTTP_404_NOT_FOUND)
    paginator = JobPagination()
    result_page = paginator.paginate_queryset(instance, request)
    serialized = ProductSerializer(result_page, many=True)
    return paginator.get_paginated_response(serialized.data)

class RegistrationView(APIView):

    def post(self, request):
        org,user_role = None,None
        if isinstance(request.user, AnonymousUser):
            user_role = None
        else:
            try:
                user_role = request.user.role.name
            except Exception as e:
                return Response("no organization",status=status.HTTP_404_NOT_FOUND)
        if request.user and user_role in ("super admin","admin") or isinstance(request.user,AnonymousUser):

            if user_role == "super admin":
                org = Organization.objects.filter(created_by = request.user).first()
                if not org:
                    return Response("User not own any organization",status=status.HTTP_404_NOT_FOUND)

            elif user_role == "admin":
                org = Organization.objects.filter(id=request.user.organization.id).first()
                if not org:
                    return Response("Organization not found",status=status.HTTP_404_NOT_FOUND)
            role = None
            if request.data.get('role',None):
                if request.data['role'].isdigit():
                    print(request.data['role'].isdigit())
                    request.data['role'] = int(request.data['role'])
                    role = Role.objects.filter(id=request.data['role']).first()
                    print(role.id)
                    if not role:
                        return Response("role not aviable", status=status.HTTP_403_FORBIDDEN)
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):

                serializer.save(organization=org,role=role)
                print(serializer.data)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):

    def post(self, request):

        email = request.data.get('email')
        password = request.data.get('password')
        print(email,password)
        user_data = authenticate(request, email=email, password=password)
        if not user_data:
            return Response("invalid credential",status=status.HTTP_401_UNAUTHORIZED)

        payload = {
            'id': user_data.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        }
        serialize = UserSerializer(instance=user_data)
        token = jwt.encode(payload, "secure", algorithm='HS256')
        response = Response()

        response.set_cookie("jwt", token, httponly=True)
        response.data = serialize.data
        return response


class UserOrganizationView(APIView):

    def get(self,request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        user_role = request.user.role
        if not user_role:
            return Response(status=status.HTTP_403_FORBIDDEN)
        user_role = user_role.name

        if user_role in ("super admin","admin"):

            user = User.objects.filter(organization_id=request.user.organization.id)
            if not user:
                return Response(status=status.HTTP_403_FORBIDDEN)

            serialized = UserSerializer(instance=user,many=True)
            print(serialized.data)
            return Response(serialized.data,status=status.HTTP_200_OK)
        return Response(status=status.HTTP_403_FORBIDDEN)




    def put(self,request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        data = request.data

        user = User.objects.filter(id=data['id'],organization_id=data['organization']).first()
        if not user:
            return Response(status=status.HTTP_404_NOT_FOUND)
        if not data or not data['role']:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(id=request.data['id']).first()
        if user:

            if user.role.name == "super admin":
                return Response("can not modify super admin",status=status.HTTP_403_FORBIDDEN)

        if request.user.id == data['id']:
            return Response("can not modify current user",status=status.HTTP_403_FORBIDDEN)


        if request.user.role.name in ('super admin','admin') and request.user.organization.id == data['organization']:

            role = Role.objects.filter(id=data['role'],organization_id=data['organization']).first()

            if not role:
                return Response(status=status.HTTP_404_NOT_FOUND)

            if role.name == 'super admin':
                return Response("can't allow to set/modify super admin role",status=status.HTTP_406_NOT_ACCEPTABLE)

            serialized = UserSerializer(instance=user,data=data,partial=True)
            if serialized.is_valid(raise_exception=True):
                # serialized.save(role=role)

                return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_401_UNAUTHORIZED)


    def delete(self,request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        data = request.data
        if not data:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        role = None
        if data['role']:
            if data['role']['name'] == "super admin":
                return Response("cannot delete super admin",status=status.HTTP_406_NOT_ACCEPTABLE)
            role = Role.objects.filter(id=data['role']['id']).first()
        if request.user.id == data['id']:
            return Response("can not delete current user",status=status.HTTP_403_FORBIDDEN)
        if request.user.organization.id == data['organization'] and request.user.role.name in ('super admin','admin'):

            user = User.objects.filter(id=data['id'], organization=request.user.organization).first()

            if not user:
                return Response("user not found", status=status.HTTP_404_NOT_FOUND)

            user.role = None
            user.organization = None
            user.save()

            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_403_FORBIDDEN)







class RoleManagement(APIView):

    def post(self,request):
        pass





class UserView(APIView):

    def get(self, request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(instance=request.user)
        response = serializer.data

        role = request.user.role
        if role:
            response['role'] = role.name
        if request.user.organization:
            response['organization'] = request.user.organization.name

        return Response(response)

    def put(self,request):

        if isinstance(request.user,AnonymousUser):
            return Response("AnonymousUser",status=status.HTTP_403_FORBIDDEN)

        user =request.user
        data = request.data
        print(data)
        if user.id != data['id']:
            return Response("user mismatch",status=status.HTTP_403_FORBIDDEN)

        serialized = UserSerializer(instance=user,data=request.data,partial=True)
        if serialized.is_valid(raise_exception=True):
            serialized.save()
            return Response(status=status.HTTP_200_OK)
        return Response("BAD_REQUEST",status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request):

        if isinstance(request.user,AnonymousUser):
            return Response("AnonymousUser",status=status.HTTP_403_FORBIDDEN)
        user = request.user
        data = request.data
        print(data)
        if user.id != data['id']:
            return Response("user mismatch", status=status.HTTP_403_FORBIDDEN)

        user.delete()
        responses = Response("success",status=status.HTTP_200_OK)
        responses.delete_cookie('jwt')
        return responses


class LogOutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie("jwt")
        response.data = {"message": "success"}
        return response

class OraganizationView(APIView):

    def post(self,request):

        if isinstance(request.user,AnonymousUser):
            return Response("AnonymousUser",status=status.HTTP_403_FORBIDDEN)

        serializer = OrganizationSerializer(data=request.data,context={'request':request})
        if serializer.is_valid(raise_exception=True):
            org = serializer.save()
            role = Role.objects.create(name="super admin",description="do anything",organization=org)
            user = request.user
            user.role = role
            user.organization = org
            user.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)

        return Response(status=status.HTTP_400_BAD_REQUEST)

    def get(self,request,name=None):

        if isinstance(request.user,AnonymousUser):
            return Response("Login required",status=status.HTTP_403_FORBIDDEN)
        org_id = request.user.organization
        if not org_id:
            return Response(status=status.HTTP_404_NOT_FOUND)
        if not name:
            instance = Organization.objects.filter(id = org_id.id)

            if not instance:
                return Response("User not own any organization",status=status.HTTP_404_NOT_FOUND)

            serialized = OrganizationSerializer(instance=instance,many=True)

            return Response(serialized.data,status=status.HTTP_200_OK)

        instance = Organization.objects.filter(name__istartswith=name)

        if not instance:
            return Response("No Organization in our database",status=status.HTTP_404_NOT_FOUND)

        serialized = OrganizationSerializer(instance=instance,many=True)
        return Response(serialized.data,status=status.HTTP_200_OK)

    def put(self,request,id):

        if isinstance(request.user,AnonymousUser):
            return Response("Login required",status=status.HTTP_403_FORBIDDEN)

        if not id:
            return Response("Organization must be specified",status=status.HTTP_403_FORBIDDEN)

        instance = Organization.objects.filter(id=id).first()

        if not instance:
            return Response("requested organization not found",status=status.HTTP_404_NOT_FOUND)

        if instance.created_by_id == request.user.id:

            serialized = OrganizationSerializer(instance=instance,data=request.data,partial=True)

            if serialized.is_valid(raise_exception=True):
                serialized.save()
                return Response(serialized.data,status=status.HTTP_200_OK)

        return Response("UNAUTHORIZED",status=status.HTTP_401_UNAUTHORIZED)

    def delete(self,request,id):

        if isinstance(request.user,AnonymousUser):
            return Response("Login required",status=status.HTTP_403_FORBIDDEN)

        if not id:
            return Response("Organization must be specified", status=status.HTTP_403_FORBIDDEN)

        instance = Organization.objects.filter(id=id).first()

        if not instance:
            return Response("requested organization not found", status=status.HTTP_404_NOT_FOUND)

        if instance.created_by_id == request.user.id:

            instance.delete()
            return Response(status=status.HTTP_200_OK)

        return Response("UNAUTHORIZED",status=status.HTTP_401_UNAUTHORIZED)



class RoleView(APIView):

    def post(self,request):

        if isinstance(request.user,AnonymousUser):
            return Response("Login required",status=status.HTTP_403_FORBIDDEN)

        role = request.data.get("name").lower()
        if not role:
            return Response("role not be empty",status=status.HTTP_403_FORBIDDEN)
        role_check = Role.objects.filter(name=role,organization=request.user.organization).first()

        if role_check:
            return Response("role already exists",status=status.HTTP_403_FORBIDDEN)

        user_role = request.user.role
        if not user_role:
            return Response(status=status.HTTP_403_FORBIDDEN)
        user_role = user_role.name

        org = Organization.objects.filter(id=request.user.organization_id).first()

        if not org:
            return Response("Not have any organization to create role", status=status.HTTP_403_FORBIDDEN)

        if role != 'super admin' and user_role in ('super admin','admin'):
            serialized = RoleSerializer(data=request.data)
            if serialized.is_valid(raise_exception=True):
                instance = serialized.save(organization = org)

                return Response("success",status=status.HTTP_201_CREATED)

        return Response("illegal action",status=status.HTTP_406_NOT_ACCEPTABLE)

    def get(self,request):

        if isinstance(request.user,AnonymousUser):
            return Response("Login required",status=status.HTTP_403_FORBIDDEN)


        org = Organization.objects.filter(id=request.user.organization_id).first()

        if not org:
            return Response("Not have any organization to create role", status=status.HTTP_403_FORBIDDEN)

        user_role = request.user.role
        if not user_role:
            return Response(status=status.HTTP_403_FORBIDDEN)
        user_role = user_role.name
        if user_role == "super admin":
            instance = Role.objects.filter(organization=org)
            serialized = RoleSerializer(instance=instance,many=True)
            return Response(serialized.data, status=status.HTTP_200_OK)
        elif user_role in ("admin"):
            instance = Role.objects.filter(organization=org).exclude(name="super admin")
            serialized = RoleSerializer(instance=instance, many=True)
            return Response(serialized.data, status=status.HTTP_200_OK)
        else:
            instance = Role.objects.filter(organization=org).exclude(name__in=["super admin","admin"])
            serialized = RoleSerializer(instance=instance, many=True)
            return Response(serialized.data, status=status.HTTP_200_OK)
        return Response("illegal action",status=status.HTTP_406_NOT_ACCEPTABLE)

    def put(self,request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        data = request.data.get('name').lower()

        org = Organization.objects.filter(id=request.user.organization_id).first()

        if not org:
            return Response("Not have any organization to create role", status=status.HTTP_403_FORBIDDEN)

        user_role = request.user.role
        if not user_role:
            return Response(status=status.HTTP_403_FORBIDDEN)
        user_role = user_role.name

        role_check = Role.objects.filter(name=data).first()

        if not role_check:
            return Response("role no longer there", status=status.HTTP_403_FORBIDDEN)

        if user_role in ("super admin","admin") and request.data['name'] != 'super admin':
            role_id = request.data.get("id")
            instance = Role.objects.filter(id=role_id).first()
            serialized = RoleSerializer(data=request.data,instance=instance,partial=True)
            if user_role == "admin" and request.user.organization.id != instance.organization.id:
                return Response(status=status.HTTP_403_FORBIDDEN)

            if serialized.is_valid(raise_exception=True):
                serialized.save()
                return Response(serialized.data,status=status.HTTP_200_OK)

        return Response(status=status.HTTP_403_FORBIDDEN)

    def delete(self,request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        data = request.data
        user = request.user

        if user.role.name in ("super admin","admin"):
            role = Role.objects.filter(id=data.get("id")).first()
            print(role.name)
            if role.name == "super admin":
                return Response("can't delete selected role",status=status.HTTP_406_NOT_ACCEPTABLE)
            if user.role == "super admin":
                org = Organization.objects.filter(created_by = user).first()
                if not org:
                    return Response("organization not found",status=status.HTTP_404_NOT_FOUND)
            if user.role == "admin" and role.organization_id != user.organization_id:
                return Response(status=status.HTTP_403_FORBIDDEN)

            role.delete()
            return Response("success",status=status.HTTP_200_OK)

        return Response(status=status.HTTP_403_FORBIDDEN)


class JobView(APIView):

    def get(self,request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)
        org = request.user.organization
        if not org:
            return Response(status=status.HTTP_404_NOT_FOUND)
        instance = Job.objects.filter(organization_id=org.id)
        if not instance:
            return Response("job not available",status=status.HTTP_404_NOT_FOUND)
        name = Organization.objects.filter(id=org.id).first()
        paginator = JobPagination()
        result_page = paginator.paginate_queryset(instance, request)
        serialized = JobSerializer(result_page, many=True)
        return paginator.get_paginated_response(serialized.data)

    def post(self,request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        user = request.user

        if user.role.name in ("super admin","admin"):
            org = None
            if user.role.name == "super admin":
                org = Organization.objects.filter(created_by = user).first()
                print(org)
                if not org:
                    return Response("org not found",status=status.HTTP_404_NOT_FOUND)
            if user.role.name == "admin":
                org = Organization.objects.filter(id=user.organization.id).first()

                if not org:
                    return Response("org not found",status=status.HTTP_404_NOT_FOUND)

            serialized = JobSerializer(data=request.data)
            if serialized.is_valid(raise_exception=True):
                serialized.save(organization=org)
                return Response(serialized.data,status=status.HTTP_201_CREATED)

        return Response(status=status.HTTP_406_NOT_ACCEPTABLE)

    def delete(self,request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        user = request.user
        org = Organization.objects.filter(id = user.organization.id).first()
        if not org:
            return Response(status=status.HTTP_404_NOT_FOUND)
        if not request.data['organization']['id']:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        if user.role.name in ("super admin","admin") and org.id == request.data['organization']['id']:

            job =  Job.objects.filter(id=request.data['id']).first()
            if not job:
                return Response(status=status.HTTP_404_NOT_FOUND)
            job.delete()
            return Response(status=status.HTTP_200_OK)

        return Response(status=status.HTTP_403_FORBIDDEN)


class ApplicationView(APIView):

    def get(self,request,aid=None):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)
        if aid:
            job = Application.objects.filter(job_id=aid)

            if not job:
                return Response(status=status.HTTP_404_NOT_FOUND)
            serialized = ApplicationSerializer(instance=job, many=True)

            return Response(serialized.data, status=status.HTTP_200_OK)
        instance = Application.objects.filter(user = request.user)

        if not instance:
            return Response("No application aviable",status=status.HTTP_404_NOT_FOUND)

        serialized = ApplicationSerializer(instance=instance,many=True)

        return Response(serialized.data,status=status.HTTP_200_OK)

    def post(self,request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)
        print(request.data)
        if not request.data.get("id"):
            return Response(status=status.HTTP_400_BAD_REQUEST)

        job = Job.objects.filter(id=request.data['id']).first()

        if not job:
            return Response("job not available",status=status.HTTP_404_NOT_FOUND)

        if Application.objects.filter(user=request.user, job=job).exists():
            return Response(
                {"detail": "You have already applied this job."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serialized = ApplicationSerializer(data=request.data,context={"user":request.user,"job":job})

        if serialized.is_valid(raise_exception=True):
            serialized.save()

            return Response("success",status=status.HTTP_200_OK)

        return Response(status=status.HTTP_403_FORBIDDEN)

    def delete(self,request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        if not request.data.get("id"):
            return Response(status=status.HTTP_403_FORBIDDEN)

        a_job = Application.objects.filter(id=request.data['id']).first()
        print(a_job)
        if not a_job:
            return Response("job not aviable",status=status.HTTP_404_NOT_FOUND)

        Application.objects.filter(id = a_job.id).delete()

        return Response("success",status=status.HTTP_200_OK)



class NewsView(APIView):

    def get(self,request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        org = News.objects.filter(organization= request.user.organization)
        if not org:
            return Response("No News",status=status.HTTP_404_NOT_FOUND)
        serialized = NewsSerializer(instance=org,many=True)

        return Response(serialized.data,status=status.HTTP_200_OK)

    def post(self,request):

        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)
        org = Organization.objects.filter(id=request.user.organization.id).first()

        if not org:
            return Response("organization not found",status=status.HTTP_404_NOT_FOUND)

        if request.user.role.name in ('super admin','admin'):

            serialized = NewsSerializer(data=request.data)
            if serialized.is_valid(raise_exception=True):
                serialized.save(organization=org,created_by=request.user)

                return Response(status=status.HTTP_201_CREATED)
        return Response(status=status.HTTP_403_FORBIDDEN)

    def put(self,request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        user = request.user
        if not request.data['id']:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if user.organization.id != request.data['organization']:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        news = News.objects.filter(id=request.data['id']).first()

        if not news:
            return Response(status=status.HTTP_404_NOT_FOUND)
        if user.role.name in ('super admin','admin'):
            serialized = NewsSerializer(instance=news,data=request.data,partial=True)
            if serialized.is_valid(raise_exception=True):
                serialized.save(created_by=request.user)
                return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_403_FORBIDDEN)

    def delete(self,request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        user = request.user
        print(request.data)
        if not request.data['id']:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        if user.organization.id != request.data['organization']:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        if user.role.name in ('super admin','admin'):

            news = News.objects.filter(id=request.data['id']).first()
            print(news)
            if not news:
                return Response("news not found",status=status.HTTP_404_NOT_FOUND)

            news.delete()

            return Response(status=status.HTTP_200_OK)

        return Response(status=status.HTTP_403_FORBIDDEN)


class ProductView(APIView):

    def get(self, request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)
        org = getattr(request.user, 'organization', None)
        if not org:
            return Response(status=status.HTTP_404_NOT_FOUND)
        instance = Product.objects.filter(organization_id=org.id)
        if not instance.exists():
            return Response("product not available", status=status.HTTP_404_NOT_FOUND)
        paginator = JobPagination()
        result_page = paginator.paginate_queryset(instance, request)
        serialized = ProductSerializer(result_page, many=True)
        return paginator.get_paginated_response(serialized.data)

    def post(self, request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        user = request.user
        if user.role.name in ("super admin", "admin"):
            org = None
            if user.role.name == "super admin":
                org = Organization.objects.filter(created_by=user).first()
                if not org:
                    return Response("org not found", status=status.HTTP_404_NOT_FOUND)
            if user.role.name == "admin":
                org = Organization.objects.filter(id=user.organization.id).first()
                if not org:
                    return Response("org not found", status=status.HTTP_404_NOT_FOUND)

            # DRF handles both form fields and files in request.data
            serializer = ProductSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save(organization=org)
                return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(status=status.HTTP_406_NOT_ACCEPTABLE)

    def delete(self, request):
        if isinstance(request.user, AnonymousUser):
            return Response("Login required", status=status.HTTP_403_FORBIDDEN)

        user = request.user
        org = Organization.objects.filter(id=user.organization.id).first()
        if not org:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # Accept both int and dict for organization
        org_id = None
        org_data = request.data.get('organization')
        if isinstance(org_data, dict):
            org_id = org_data.get('id')
        else:
            org_id = org_data

        if not org_id:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if user.role.name in ("super admin", "admin") and org.id == org_id:
            product = Product.objects.filter(id=request.data['id']).first()
            if not product:
                return Response(status=status.HTTP_404_NOT_FOUND)
            product.delete()
            return Response(status=status.HTTP_200_OK)

        return Response(status=status.HTTP_403_FORBIDDEN)