from rest_framework import serializers
from django.contrib.auth.models import User
from TodoListApi.models import UserTodo,TodoList,LogUser,ListContent

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

class ListContentSerializer(serializers.ModelSerializer):
    class Meta:
        model= ListContent
        fields= '__all__'

class TodoListSerializer(serializers.ModelSerializer):
    user = UserTodoSerializer(read_only=True)
    #image = serializers.SerializerMethodField('get_image_url')
    listcontent = ListContentSerializer(many=True)
    class Meta:
        model = TodoList
        fields = ('id','user','title','description','listcontent','image','modified')

    def get_image_url(self, sliderimage):
        request = self.context.get('request')
        image = sliderimage.image.url
        return request.build_absolute_uri(image)

