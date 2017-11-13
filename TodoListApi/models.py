from django.db import models
from django.contrib.auth.models import User
from ckeditor_uploader.fields import RichTextUploadingField
from django.utils.translation import ugettext_lazy as _
# Create your models here.
class UserTodo(models.Model):
    NORMAL = 'Normal'
    ADMIN = 'Admin'

    CHOICES_TYPE = (
        (NORMAL,_('Normal')),
        (ADMIN,_('Admin')),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    type_user = models.CharField(_('type_user'), choices=CHOICES_TYPE, max_length=30, default=NORMAL)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True, editable=False)

    def __str__(self):
        return self.user.email

    def __unicode__(self):
        return self.user.email if self.user is not None else self.user.username
    class Meta:
        verbose_name_plural = "User TodoLists"

class LogUser(models.Model):
    user = models.ForeignKey('UserTodo', related_name='Logusers', verbose_name=_('User'), null=True)
    action = models.CharField(_('Action'), max_length=100, blank=True,null=True)
    table = models.CharField(_('Table'), max_length=30, blank=True,null=True)
    fileds = models.CharField(_('Fields'), max_length=255, blank=True,null=True)
    values = models.CharField(_('Values'), max_length=255, blank=True,null=True)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True, editable=False)

    def __str__(self):
        return str("LogUser "+self.id)

    def __unicode__(self):
        return str("LogUser "+self.id)

    class Meta:
        verbose_name_plural = "LogUsers"

class TodoList(models.Model):
    user = models.ForeignKey('UserTodo', related_name='usertodolist', verbose_name=_('User'), null=True)
    title = models.CharField(_('Title'),max_length=100)
    image = models.ImageField(_('Image'), blank=True,null=True,upload_to='media/')
    description = RichTextUploadingField(_('Description'),blank=False, null=False)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True, editable=False)
    
    def __str__(self):
        return str(self.id)

    def __unicode__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = "TodoLists"

class ListContent(models.Model):
    todolist = models.ForeignKey('TodoList', related_name='todolistcontent', verbose_name=_('TodoList'), null=True)
    description= models.CharField(_('Description'),max_length=255)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True, editable=False)
    
    def __str__(self):
        return str(self.id)

    def __unicode__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = "ListsContent"