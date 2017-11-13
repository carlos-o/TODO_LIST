from rest_framework import serializers
from django.contrib.auth.models import User
from TodoListApi.models import UserTodo,TodoList,LogUser

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username','first_name', 'last_name', 'email')

class UserTodoSerializer(serializers.ModelSerializer):
    #user = UserSerializer(read_only=True)
    username = serializers.CharField(source='user.username')
    email = serializers.CharField(source='user.email')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')
    class Meta:
        model = UserTodo
        #fields = ('id','user','type_user',)
        fields =('id','username','first_name','last_name', 'email','type_user')
