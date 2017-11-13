from django.conf import settings
from django.core.mail import EmailMessage
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.shortcuts import render
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import F
from django.db.models import Sum
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework import authentication, permissions
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.response import Response
from rest_framework import status
from .models import UserTodo,TodoList,LogUser
from .serializers import UserTodoSerializer#, TodoListSerializer, LogUserSerializer 
import datetime
import time
import random
import re
import string
from rest_framework_jwt.settings import api_settings

STATUS_200 = status.HTTP_200_OK
STATUS_201 = status.HTTP_201_CREATED
STATUS_202 = status.HTTP_202_ACCEPTED
STATUS_204 = status.HTTP_204_NO_CONTENT
STATUS_400 = status.HTTP_400_BAD_REQUEST
STATUS_401 = status.HTTP_401_UNAUTHORIZED
STATUS_404 = status.HTTP_404_NOT_FOUND
STATUS_500 = status.HTTP_500_INTERNAL_SERVER_ERROR

def pass_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
class UserList(APIView):
    permission_classes = (permissions.AllowAny,)
    def get(self, request,):
        user = UserTodo.objects.all()
        serializer = UserTodoSerializer(user, many=True)
        return Response(serializer.data)

class UserDetail(APIView):
    permission_classes = (permissions.AllowAny,)
    def get_object(self, pk):
        try:
            return UserTodo.objects.get(pk=pk)
        except UserTodo.DoesNotExist:
            raise Http404
    
    def get(self,request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserTodoSerializer(user)
        return Response(serializer.data)

class RegisterView(APIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request):
        data ={}
        find_user = User.objects.filter(email=request.data.get('email'))
        if (len(find_user)== 0):
            user = User.objects.create_user(username=request.data.get('username'), email=request.data.get('email'),
                                            password=request.data.get('password'), first_name=request.data.get('first_name'),
                                            last_name=request.data.get('last_name'))
            userdata = UserTodo.objects.create(user=user)

            data['pk'] = userdata.pk
            data['first_name']= user.first_name
            data['last_name']= user.last_name
            data['username'] = user.username
            data['email'] = user.email
            data['type'] = str(userdata.type_user)
            data['response']= 'the creation of account has been successfully'
        else:
            userdata = UserTodo.objects.filter(user=find_user)
            data['username'] = find_user[0].username
            data['email'] = find_user[0].email
            data['type'] = str(userdata[0].type_user)
            data['response'] = 'the user has already been registered'
            return Response(data, status=STATUS_400)
        return Response(data, status=STATUS_201)

class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request):
        data={}
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        try:
            user = User.objects.get(email=request.data.get('email'))
        except User.DoesNotExist:
            return Response({'response':'The user not exist'},status=STATUS_404)
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)
        userdata = UserTodo.objects.get(user=user)
        pwd = str(request.data.get('password'))
        if user.check_password(pwd):
            #token = Token.objects.get_or_create(user=user)
            data['pk'] = userdata.pk
            data['first_name']= user.first_name
            data['last_name']= user.last_name
            data['username'] = user.username
            data['email'] = user.email
            data['token'] = token
            data['type'] = str(userdata.type_user)
            data['response']= 'the user has connected to the system'
            return Response(data, status=STATUS_200)
        else:
            data['response'] = 'the user password is incorrect'
            return Response(data, status=STATUS_401)

class RecoverAndChangePasswordView(APIView):
    permission_classes = (permissions.AllowAny,)
    def get_object(self,email):
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            raise Http404
            
    def post(self, request,):
        user = self.get_object(request.data.get('email'))
        userdata = UserTodo.objects.get(user=user)
        new_password = pass_generator(6)
        userdata.user.set_password(new_password)
        print(new_password)
        send_mail('Hello '+str(userdata.user.username),'this the your new password '+str(new_password), 'Admin@TodoList.com', [str(userdata.user.email)], fail_silently=False)
        return Response({'response':'the new password has been sent please check your email'}, status=STATUS_200)

    def put(self, request,):
        data = {}
        pwd_old = request.data.get('password_old')
        pwd_new = request.data.get('password_new')
        user = self.get_object(request.data.get('email'))
        userdata = UserTodo.objects.get(user=user)
        if user.check_password(pwd_old):
            userdata.user.set_password(pwd_new)
            userdata.user.save()
            data['pk'] = userdata.pk
            data['first_name']= user.first_name
            data['last_name']= user.last_name
            data['username'] = user.username
            data['email'] = user.email
            data['type'] = str(userdata.type_user)
            data['response']='the password has been changed'
            return Response(data)
        else:
            data['response']='the password you entered is incorrect'
            return Response(data, status=STATUS_400)

class RestrictedView(APIView):
    permission_classes = (IsAuthenticated, )
    authentication_classes = (JSONWebTokenAuthentication, )

    def get(self, request):
        data = {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'token': str(request.auth)
        }
        return Response(data)