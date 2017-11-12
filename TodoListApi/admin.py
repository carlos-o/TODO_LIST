from django.contrib import admin
from .models import UserTodo,TodoList
# Register your models here.


@admin.register(UserTodo)
class UserTodoAdmin(admin.ModelAdmin):
    pass

@admin.register(TodoList)
class TodoListAdmin(admin.ModelAdmin):
    list_display = ('pk','title','created','modified')
    list_filter = ('created','modified')

