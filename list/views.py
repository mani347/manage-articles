from django.shortcuts import render
import sys
from .models import Categories, Users, Articles
from base64 import b64encode
from django.db.models import Q, F
from django.core.files.storage import default_storage
from articles import settings
import os


def dashboard(request):
    try:
        if 'user_id' not in request.session:
            return render(request, 'list/login.html', {})
        print(request.session['user_id'])
        user = Users.objects.get(pk=request.session['user_id'])
        pref = user.categories_pref
        if pref != '':
            pref = list(map(int, pref.split(',')))
        else:
            pref = []
        blocked_articles = []
        if user.blocked_articles != '':
            blocked_articles = list(map(int, user.blocked_articles))
        if len(pref) <= 0:
            articles = Articles.objects.all()
        else:
            articles = Articles.objects.filter(category__pk__in=pref)
        articles_list = []
        for article in articles:
            if article.pk in blocked_articles:
                continue
            d = dict()
            d['id'] = article.pk
            d['title'] = article.title
            d['desc'] = article.description
            d['category'] = article.category.name
            d['likes'] = article.likes
            d['image'] = article.image
            articles_list.append(d)
        return render(request, 'list/dashboard.html', {'context': {'articles': articles_list}})
    except Exception as e:
        print("Exception in dashboard: " + str(e) + " line {}".format(sys.exc_info()[-1].tb_lineno))


def login(request):
    if request.method == 'POST':
        email = request.POST.get('inputEmail')
        password = request.POST.get('inputPassword')
        hashed_pwd = b64encode(password.encode('utf-8'))
        users = Users.objects.filter(email=email, password=hashed_pwd)
        if len(users) <= 0:
            return render(request, 'list/login.html', {'context': {'message': 'Invalid Email or Password.'}})
        request.session['user_id'] = users[0].pk
        return dashboard(request)
    return render(request, 'list/login.html', {})


def signup(request):
    if request.method == 'POST':
        first_name = request.POST.get('firstName')
        last_name = request.POST.get('lastName')
        email = request.POST.get('inputEmail')
        phone = request.POST.get('phone')
        password = request.POST.get('inputPassword')
        cpassword = request.POST.get('confirmPassword')
        preferences = request.POST.getlist('preferences')
        message = ''
        if password != cpassword:
            message = 'Password and Confirm Password not matched.'
        elif len(phone) != 10:
            message = 'Enter valid Phone.'
        if message == '':
            users = Users.objects.filter(Q(email=email) | Q(phone=phone))
            if len(users) > 0:
                message = "Email or Phone already registered."
        if message != '':
            categories = Categories.objects.all()
            categories_dict = []
            for cat in categories:
                d = dict()
                d['id'] = str(cat.pk)
                d['name'] = cat.name
                categories_dict.append(d)
            context = {'context': {'fname': first_name, 'lname': last_name, 'email': email, 'phone': phone,
                                   'categories': categories_dict, 'message': message, 'preferences': preferences}}
            return render(request, 'list/signup.html', context)

        hashed_pwd = b64encode(password.encode('utf-8'))
        new_user = Users(first_name=first_name, last_name=last_name, email=email, phone=phone, password=hashed_pwd,
                         categories_pref=','.join(preferences))
        new_user.save()
        message = 'You Registered Successfully.'
        return render(request, 'list/login.html', {'context': {'message': message}})
    categories = Categories.objects.all()
    categories_dict = []
    for cat in categories:
        d = dict()
        d['id'] = str(cat.pk)
        d['name'] = cat.name
        categories_dict.append(d)
    context = {'context': {'categories': categories_dict}}
    return render(request, 'list/signup.html', context)


def my_articles(request):
    if 'user_id' not in request.session:
        return render(request, 'list/login.html', {})
    print(request.session['user_id'])
    articles = Articles.objects.filter(created_by__pk=request.session['user_id'])
    articles_list = []
    for article in articles:
        d = dict()
        d['id'] = article.id
        d['title'] = article.title
        d['desc'] = article.description
        d['category'] = article.category.name
        d['likes'] = article.likes
        d['image'] = article.image
        d['dislikes'] = article.dislikes
        articles_list.append(d)
    return render(request, 'list/my_articles.html', {'context': {'articles': articles_list}})


def write_article(request):
    try:
        if 'user_id' not in request.session:
            return render(request, 'list/login.html', {})
        print(request.session['user_id'])
        message = ''
        if request.method == 'POST':
            title = request.POST.get('title')
            desc = request.POST.get('desc')
            category_id = request.POST.get('category')
            new_url = ''
            if len(request.FILES) > 0:
                image = request.FILES.get('image')
                default_storage.save(image.name, image)
                init_url = settings.BASE_DIR + default_storage.url(image.name)
                new_url = settings.BASE_DIR + '/media/images/' + str(image.name)
                os.rename(init_url, new_url)
            print(request.FILES)
            tags = request.POST.get('tags')
            user = Users.objects.get(pk=request.session['user_id'])
            category = Categories.objects.get(pk=int(category_id))
            new_article = Articles(category=category, created_by=user, title=title, description=desc, image=new_url, tags=tags)
            new_article.save()
            message = "Article submitted"
        articles = Articles.objects.filter(created_by__pk=request.session['user_id'])
        articles_list = []
        for article in articles:
            d = dict()
            d['id'] = article.id
            d['title'] = article.title
            d['desc'] = article.description
            d['category'] = article.category.name
            d['likes'] = article.likes
            d['image'] = article.image
            d['dislikes'] = article.dislikes
            articles_list.append(d)
        categories = Categories.objects.all()
        cat_list = []
        for cat in categories:
            d = dict()
            d['id'] = cat.pk
            d['name'] = cat.name
            cat_list.append(d)
        return render(request, 'list/write_article.html', {'context': {'articles': articles_list, 'categories': cat_list, 'message': message}})
    except Exception as e:
        print("Exception in write_article: " + str(e) + " line {}".format(sys.exc_info()[-1].tb_lineno))


def change_password(request):
    if 'user_id' not in request.session:
        return render(request, 'list/login.html', {})
    if request.method == "POST":
        password = request.POST.get('password')
        new_password = request.POST.get('npassword')
        conf_password = request.POST.get('cpassword')
        print(password)
        print(new_password)
        print(conf_password)
        old_hash_pasword = b64encode(password.encode('utf-8'))
        print(old_hash_pasword)
        user_id = request.session['user_id']
        user = Users.objects.get(pk=user_id)
        print(user.password == old_hash_pasword)
        message = ''
        print(user.password)
        if str(user.password) != str(old_hash_pasword):
            message = "old password not matched"
        if message == '' and new_password != conf_password:
            message = "new password and confirm password not matched"
        if message != '':
            return render(request, 'list/change_password.html', {'context': {'message': message}})
        new_hash_pwd = b64encode(new_password.encode('utf-8'))
        user.password = new_hash_pwd
        user.save()
        return logout(request)
    return render(request, 'list/change_password.html', {})


def change_pref(request):
    if 'user_id' not in request.session:
        return render(request, 'list/login.html', {})
    if request.method == 'POST':
        preferences = request.POST.getlist('preferences')
        new_pref = ','.join(preferences)
        print(new_pref)
        Users.objects.filter(pk=request.session['user_id']).update(categories_pref=new_pref)
        return dashboard(request)
    categories = Categories.objects.all()
    cat_list = []
    for cat in categories:
        d = dict()
        d['id'] = cat.pk
        d['name'] = cat.name
        cat_list.append(d)
    user = Users.objects.get(pk=request.session['user_id'])
    if len(user.categories_pref) > 0:
        user_prefs = user.categories_pref.split(',')
        user_prefs = list(map(int, user_prefs))
    else:
        user_prefs = []
    return render(request, 'list/change_preferences.html', {'context': {'categories': cat_list, 'user_prefs': user_prefs}})


def likes(request):
    if 'user_id' not in request.session:
        return render(request, 'list/login.html', {})
    article_id = request.GET.get('id')
    Articles.objects.filter(pk=article_id).update(likes=F('likes') + 1)
    return dashboard(request)


def dislikes(request):
    if 'user_id' not in request.session:
        return render(request, 'list/login.html', {})
    article_id = request.GET.get('id')
    Articles.objects.filter(pk=article_id).update(dislikes=F('dislikes') + 1)
    return dashboard(request)


def block(request):
    if 'user_id' not in request.session:
        return render(request, 'list/login.html', {})
    article_id = request.GET.get('id')
    user = Users.objects.get(pk=request.session['user_id'])
    blocks = user.blocked_articles
    if blocks == '':
        user.blocked_articles = str(article_id)
    else:
        user.blocked_articles = blocks + "," + str(article_id)
    user.save()
    return dashboard(request)


def delete_article(request):
    if 'user_id' not in request.session:
        return render(request, 'list/login.html', {})
    # print(reqeust.GET.get('id'))
    Articles.objects.filter(pk=request.GET.get('id')).delete()
    return write_article(request)


def edit_article(request):
    if 'user_id' not in request.session:
        return render(request, 'list/login.html', {})
    if request.method == "POST":
        article_id = request.POST.get('article_id')
        desc = request.POST.get('desc')
        tags = request.POST.get('tags')
        category = request.POST.get('category')
        title = request.POST.get('title')
        category = Categories.objects.get(pk=category)
        Articles.objects.filter(pk=article_id).update(title=title, tags=tags, category=category, description=desc)
        return dashboard(request)
    article_id = None
    try:
        article_id = request.GET.get('id')
    except Exception as e:
        pass
    if article_id is not None:
        article = Articles.objects.get(pk=article_id)
        categories = Categories.objects.all()
        cat_list = []
        for cat in categories:
            d = dict()
            d['id'] = cat.pk
            d['name'] = cat.name
            cat_list.append(d)
        actual_art = dict()
        actual_art['id'] = article.pk
        actual_art['title'] = article.title
        actual_art['desc'] = article.description
        actual_art['tags'] = article.tags
        actual_art['cat'] = article.category.pk
        context = {'context': {'article': actual_art, 'categories': cat_list}}
    return render(request, 'list/edit_article.html', context)


def logout(request):
    del request.session['user_id']
    return render(request, 'list/login.html', {})
