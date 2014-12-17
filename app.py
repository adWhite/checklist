import datetime
import os
import requests
from flask import Flask, request, render_template, redirect, url_for, get_flashed_messages, flash
from hashids import Hashids
import json
from bson import ObjectId
from bson.json_util import dumps
import pymongo
from pymongo import Connection
from flask.ext.login import (LoginManager, UserMixin, AnonymousUserMixin,
        current_user, login_user,
        logout_user, user_logged_in, user_logged_out,
        user_loaded_from_cookie, user_login_confirmed,
        user_loaded_from_header, user_loaded_from_request,
        user_unauthorized, user_needs_refresh,
        make_next_param, login_url, login_fresh,
        login_required, session_protected,
        fresh_login_required, confirm_login,
        encode_cookie, decode_cookie, _secret_key, 
        _user_context_processor, user_accessed)
from flask_wtf import Form
from wtforms import StringField, TextField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email
from flask.ext.assets import Environment, Bundle
from flask.ext.wtf.recaptcha import RecaptchaField
from passlib.hash import pbkdf2_sha256, md5_crypt
import scss

SALT = "devsalt"

app = Flask(__name__)

# config
app.config.from_pyfile('config.cfg')

# assets
assets = Environment(app)
assets.url = app.static_url_path
scss = Bundle('scss/style.scss', filters='pyscss', output='css/style.css')
assets.register('scss_all', scss)

# mongo setup
DATABASE_HOST = os.getenv('MONGODB_HOST', 'localhost')
DATABASE_NAME = os.getenv('MONGODB_DATABASE', 'checklist')
DATABASE_PORT = int(os.getenv('MONGODB_PORT', 27017)) 

connection = Connection(DATABASE_HOST, DATABASE_PORT)
db = connection[DATABASE_NAME]

users = db.users
projects = db.projects
tasks = db.tasks
comments = db.comments

# classes
class User(UserMixin):
    def __init__(self, username, email, password):
        self.username = username
        self.email = email 
        self.password = password
        self.active = True

    def is_authenticated(self):
        return True

    def is_active(self):
        # Here you should write whatever the code is
        # that checks the database if your user is active
        return True 

    def is_anonymous(self):
        return False

    def get_id(self):
        user = users.find_one({'username':self.username})['_id']
        return unicode(str(user))

class Project():
    def __init__(self, id, user_id, created_at, title, client):
        self.id = id
        self.user_id = user_id
        self.title = title
        self.created_at = created_at
        self.client = client

    def add_comment(created_at, author, comment):
        comment_id = get_new_id(comments)
        comments.insert({'_id':comment_id, 'author':author, 'comment':comment, 'created_at':created_at, 'project_id':self.id})
        return redirect(url_for('project/' + self.id))

    def remove_comment(author, id):
        comment = comments.find_one({'_id':id})
        if author == comment['author']:
            comments.remove({'_id':id})
            return redirect(url_for('project/' + self.id))


class FormAddProject(Form):
    title = TextField('title', validators=[DataRequired()])


class FormLogin(Form):
    email = TextField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    # recaptcha = RecaptchaField()


class FormRegister(Form):
    username = TextField('username', validators=[DataRequired()])
    email = TextField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    # recaptcha = RecaptchaField()


# Creating a login manager instance
login_manager = LoginManager()
# Configuring
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # 1. Fetch against the database a user by `id` 
    user = users.find_one({'_id':user_id})
    # 2. Create a new object of `User` class and return it
    return User(user['username'], user['email'], user['password'])

# methods 
def get_date():
    return str(datetime.datetime.now()).split('.')[0]

def pass_hash(password):
        return pbkdf2_sha256.encrypt(password, rounds=8000, salt_size=16)

def pass_check(username, password):
    password_hashed = users.find_one({'username': username})['password']
    return pbkdf2_sha256.verify(password, password_hashed)

def get_new_id(model):
    hashids = Hashids(salt=SALT, min_length="6") 
    try:
        id = model.find({}).count() + 1
    except:
        id = 0
    return hashids.encrypt(id)

# routes 
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = FormRegister()
    if current_user.is_authenticated():
        return redirect(url_for('user'))
    elif request.method == 'POST' and 'username' in request.form:
        if form.validate_on_submit():
            username = request.form['username']
            email = request.form['email']
            password = pass_hash(request.form['password'])
            if users.find_one({'username': username}):
                flash('Username already in use')
            elif users.find_one({'email': email}):
                flash('Email already in use')
            else:
                _id = get_new_id(users)
                users.insert({'_id': _id, 'username':username, 'email':email, 'password':password})
                flash('User created successfully')
                return redirect(url_for('user'))
        else:
            flash('Please enter the information in the form')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = FormLogin()
    if current_user.is_authenticated():
        return redirect(url_for('index'))
    elif request.method == 'POST' and 'email' in request.form:
        email = request.form['email']
        password = request.form['password']
        hashed_password = pass_hash(password)
        if form.validate_on_submit():
            if users.find_one({'email':email}):
                username = users.find_one({'email':email})['username']
                if pass_check(username, password):
                    user = User(username, email, hashed_password)
                    if login_user(user):
                        flash('Logged in successfully')
                        return redirect(url_for('user'))
                    else:
                        flash('Sorry, but you couldn\'t log in')
                else:
                    flash('Wrong password')
            else:
                flash('User with that email doesn\'t exist')
        else:
            flash('Please enter your email and password')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# @app.route('/app')
# def app():
#     return ""
 
@app.route('/user')
def user():
    if current_user.is_authenticated():
        return render_template('user.html')
    else:
        flash('You need to be logged in to see the profile page')
        return redirect(url_for('index'))

@app.route('/projects')
def all_projects():
    if current_user.is_authenticated():
        project_list = projects.find({})
        return render_template('projects.html', project_list=project_list)
    else:
        flash('You need to be logged in to view the projects list')
        return redirect(url_for('login'))

@app.route('/projects/add', methods=['GET', 'POST'])
def add_project():
    form = FormAddProject()
    if current_user.is_authenticated():
        if request.method == 'POST' and 'title' in request.form:
            if form.validate_on_submit():
                project_id = get_new_id(projects)
                created_at = get_date()
                title = request.form['title']
                author = current_user.username
                user_id = users.find_one({'username':author})['_id']
                projects.insert({'_id':project_id, 'created_at':created_at, 'title':title, 'user_id':user_id, 'author':author})
                flash('Project: ' + title + ' created successfully')
                return redirect(url_for('all_projects'))
    else: 
        flash('You need to be logged in to create a new project')
        return redirect(url_for('login'))
    return render_template('new-project.html', form=form)

@app.route('/project/<id>')
def project(id=id):
    if current_user.is_authenticated():
        current_project = projects.find_one({'_id':id})
        project_id = current_project['_id']
        project_title = current_project['title']
        project_author = current_project['author']
        tasks_list = tasks.find({'project_id':project_id})
        return render_template('project.html', title=project_title, author=project_author, id=project_id, tasks=tasks_list)
    else:
        flash('Need to be logged in to view projects')
        return redirect(url_for('login'))

@app.route('/task/add', methods=['GET', 'POST'])
def add_task():
    project_id = request.form['projectId']
    task_title = request.form['title']
    task_author = request.form['author']
    task_date = get_date()
    if tasks.find_one({'title': task_title}):
        return json.dumps({'fail': 'Task already exists'})
    elif users.find_one({'username': task_author}):
        id = get_new_id(tasks)
        tasks.insert({'_id':id, 'title':task_title, 'project_id':project_id, 'author':task_author, 'created_at':task_date})
        return json.dumps({ 'success': 200 })

if __name__ == '__main__':
    app.run()
