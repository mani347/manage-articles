from django.urls import path
from . import views
from articles import settings
from django.views.static import serve

app_name = 'list'
urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('signup', views.signup, name='signup'),
    path('login', views.login, name='login'),
    path('my-articles', views.my_articles, name='my_articles'),
    path('write-article', views.write_article, name='write_article'),
    path('my-articles', views.my_articles, name='my-articles'),
    path('change-password', views.change_password, name='change_password'),
    path('change-pref', views.change_pref, name='change_pref'),
    path('likes', views.likes, name='likes'),
    path('dislikes', views.dislikes, name='dislikes'),
    path('block', views.block, name='block'),
    path('delete-article', views.delete_article, name='delete_article'),
    path('edit-article', views.edit_article, name='edit_article'),
    path('logout', views.logout, name='logout'),
    # path('media/', serve, {'document_root': settings.MEDIA_ROOT}),
]
