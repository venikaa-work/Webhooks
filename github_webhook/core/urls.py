
from django.urls import path
from . import views
urlpatterns = [
    path('api/test/', views.hello, name='hello')
]
