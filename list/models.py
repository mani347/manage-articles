from django.db import models


class Categories(models.Model):
    name = models.CharField(max_length=255)

    class Meta:
        db_table = 'categories'


class Users(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.CharField(max_length=150)
    phone = models.CharField(max_length=10)
    password = models.CharField(max_length=20)
    categories_pref = models.TextField()
    blocked_articles = models.TextField(default='')

    class Meta:
        db_table = 'users'


class Articles(models.Model):
    category = models.ForeignKey(Categories, on_delete=models.CASCADE)
    created_by = models.ForeignKey(Users, on_delete=models.CASCADE)
    title = models.TextField()
    description = models.TextField()
    tags = models.TextField()
    image = models.TextField()
    likes = models.IntegerField(default=0)
    dislikes = models.IntegerField(default=0)

    class Meta:
        db_table = 'articles'
