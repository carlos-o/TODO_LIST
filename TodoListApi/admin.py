from django.contrib import admin
from .models import UserTodo,TodoList,ListContent
# Register your models here.


@admin.register(UserTodo)
class UserTodoAdmin(admin.ModelAdmin):
    pass


class ListContentInline(admin.StackedInline):
    model = ListContent
    extra = 3

@admin.register(TodoList)
class TodoListAdmin(admin.ModelAdmin):
    list_display = ('pk','title','created','modified')
    list_filter = ('created','modified')
    inlines = (ListContentInline,)