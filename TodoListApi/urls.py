from django.conf.urls import url, include
from django.contrib import admin
from TodoListApi import views
from rest_framework_jwt.views import obtain_jwt_token
from rest_framework_jwt.views import refresh_jwt_token
from rest_framework_jwt.views import verify_jwt_token

urlpatterns = [
    #url(r'^admin/', admin.site.urls),
    url(r'^users/$', views.UserList.as_view()),
    url(r'^users/(?P<pk>[0-9]+)/$', views.UserDetail.as_view()),
    url(r'^register/$', views.RegisterView.as_view()),
    #url(r'^login/', obtain_jwt_token),
    url(r'^login/', views.LoginView.as_view()),
    url(r'^logout/', refresh_jwt_token),
    url(r'^restricted/$', views.RestrictedView.as_view()),

]
