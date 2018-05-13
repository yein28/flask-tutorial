# Flaskr

https://tech.ssut.me/2017/03/24/python-functions-are-first-class

-> Python's Functions Are First-Class

**WSGI(Web Server Gateway Interface)**

- describes how a web server communicates with web applications
- how web applications can be chained togerther to process one request

**Werkzeug**

- WSGI utility library for Python 

  

**폴더 생성**

- static : CSS와 javascript 파일들 저장
- templates : Jinja2 템플릿이 저장



**데이터베이스 스키마**

`vi schema.sql `

````sql
drop table if exist entries;
create table entries (
	id integer primary key autoincrement,
	title string not null,
	text sgring not null
);
````



**Application Factory**

Application Factory : create funtion inside the Flask instance

- `__init__.py`
  - application factory 를 포함
  - 이 디렉토리는 package로 treated 되어야한다고 알림
- `__name__` : name of current Python module
- `instane_relative_config=True `
  - configutaion 파일들이 instance 폴더에 상대적이란걸 app에 알림
  - instance 폴더는 flaskr 패키지의 밖에 위치, vc에 커밋되지 않는 로컬 데이터( configuration secret이나 데이터 베이스 파일 )를 가지고 있음
- `app.config.from_mapping()`: app이 사용할 몇가지 default configuration 세팅
  - `SECRET_KEY` : 데이터를 안전하게 보호하기 위한 기능
    - `'dev'` 개발할때 만 세팅, 배포 시에는 랜덤한 값으로 덮어씌워져야함
  - `DATABASE` : SQLite DB 파일이 저장될 경로를 지정
    - `'app.instance_path'`:  instance folder에서 가져오는 값
- `app.config.from_pyfile()` :  default configuration value 값을 instance 폴더의 config.py에서 가져와 덮어씌움
- `os.makedirs()` : app.instance_path 가 존재한다는 것을 보장
  - Flask가 instance 폴더를 자동으로 생성하지 않음 
- ` @app.route()`  : <a href="#decorator">decorator<a> that is used to register a view function for a given URL rule.



**Run The Application**

````
export FLASK_APP=flaskr
export FLASK_ENV=development
flask run
````

-> https://blog.outsider.ne.kr/1306 환경변수를 .envrc에 넣고 관리



**Define and Access the Database**

- python 의 built-in 모듈 - sqlite3 사용, App 이 작기 때문에 그냥 사용

`flaskr/db.py`

````python
import sqlite3

import click
from flask import current_app, g
# g : 각각의 요청에 대해 고유한 오브젝트, 요청이 수행되는 동안 여러 함수에서 접근할 수 있는 데이터를 저장하는데 사용, 똑같은 요청에서 get_db가 다시 호출되더라도 새로운 connection이 만들어지지않음

from flask.cli import with_appcontext

def get_db():
	if 'db' not in g:
		g.db = sqlite3.connect(
			curent_app.config['DATABASE'],
			detect_types=sqlite3.PARSE_DECLTYPES
		)
        # sqlite3.connect() : DATABASE 키가 가리키는 곳과 연결 수립
		g.db.row_factory = sqlite3.Row
        # sqlite3.Row : 연결이 dict 처럼 행동하는 row들을 반환, 컬럼을 이름으로 접근할 수 있도록 해줌
	return g.db

def close_db(e=None):
	db = g.pop('db', None )

	if db is not None:
		db.close()
        
def init_db():
    db = get_db() # return database connection

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))
	
@click.command('init-db')
@with_appcontext
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

def init_app(app):
  	# tells Flask to call that function when cleaning up after returning the response. 
    app.teardown_appcontext(close_db)
    # add new command that can be called with the flask command
    app.cli.add_command(init_db_command)
````



**Blueprints and Views**

`flaskr/__init__.py`

````python
import os

from flask import Flask

def create_app(test_config=None):
	# create and configure the app
	app = Flask(__name__, instance_relative_config=True) # creates the flask instance

	app.config.from_mapping(
		SECRET_KEY='dev',
		DATABASE=os.path.join(app.instance_path, 'flask.sqlite' ),
	)
	
	if test_config is None:
		# load the instance config, if it exists, when not testing
		app.config.from_pyfile('config.py', silent=True)
	else:
		# load the test config if passed in
		app.config.from_mapping(test_config)

	# ensure the instance folder exists
	try:
		os.makedirs(app.instance_path)
	except OSError:
		pass

	# a simple page that says hello
	@app.route('/hello')
	def hello():
		return 'Hello, World!'

	from . import db
	db.init_app(app)

	from . import auth
    # auth에서 정의한 bluepoint를 등록
	app.register_blueprint(auth.bp)

	from . import blog
    # blog에서 정의한 bluepoint를 등록
	app.register_blueprint(blog.bp)
	app.add_url_rule('/', endpoint='index' )

	return app
````



**Create a Blueprint**

- 인증과 관련된 auth와 블로그에 관련된 blog 블루프린트 총 2개

`flaskr/auth.py`

````python
import functools

from flask import (
	Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

# creates Blueprint named 'auth'
bp = Blueprint('auth', __name__, url_prefix='/auth')

# /auth/register로 요청이 들어올때 수행될 view function
@bp.route('/register', methods=('GET', 'POST'))
def register():
	if request.method == 'POST':
		# validate the input
		username = request.form['username']
		# request.form : special type of dict mapping submitted form keys and values
		password = request.form['password']
		db = get_db()
		error = None

		if not username:
			error = 'Username is required.'
		elif not password:
			error = 'Password is required.'
		elif db.execute(
			# execute query and return first row	
			'SELECT id FROM user WHERE username = ?', (username,)
			).fetchone() is not None:
			error = 'User {} is already registered.'.format(username)
		if error is None:
			db.execute(
				'INSER INTO user (username, password) VALUES (?,?)', (username, 								generate_password_hash(password))
			)
			db.commit()
			return redirect(url_for('auth.login'))
		
		# if validation fail, show error to user
		# flash() : send message to next request, template call get_flashed_messages()
		flash(error)
	return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		db = get_db()
		error = None
		user = db.execute(
			'SELECT * FROM user WHERE username = ?', (username,)
		).fetchone()

		if user is None:
			error = 'Incorrect username.'
		elif not check_password_hash(user['password'], password ):
			error = 'Incorrect password.'

		if error is None:
			session.clear()
			session['user_id'] = user['id']
			return redirect(url_for('index'))

		flash(error)

	return render_template('auth/login.html')

# function that execute before view function
# Like Flask.before_request()
@bp.before_app_request
# 우선 세션에 등록된 유저가 있는지 확인하고 있을경우 db에서 정보를 가져옴
def load_logged_in_user():
	user_id = session.get('user_id')

	if user_id is None:
		g.user = None
	else:
		g.user = get_db().execute(
			'SELCT * FROM user WHERE id = ?', (user_id,)
		).fetchone()

@bp.route('/logout')
def logout():
	session.clear() # 로그아웃시 세션에서 삭제 
	return redirect(url_for('index'))

# 로그인을 필요로하는 view에서 데코레이터로 사용
def login_required(view):
	@functools.wraps(view)
	def wrapped_view(**kwargs):
		if g.user is None:
            # url_for : URL을 생성
			return redirect(url_for('auth.login'))

		return view(**kwargs)
	return wrapped_view
````



`flaskr/blog.py`

````python
from flask import(
	Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required
from flaskr.db import get_db

# blog blueprint 생성
bp = Blueprint('blog', __name__ )

# 메인화면, db에 저장된 글들을 index.html에 인자로 넘겨서 렌더링
@bp.route('/')
def index():
	db = get_db()
	posts = db.execute(
		'SELECT p.id, title, body, created, author_id, username'
		' FROM post p JOIN user u ON p.author_id = u.id'
		' ORDER BY created DESC'
	).fetchall()
	return render_template('blog/index.html', posts=posts)

@bp.route('/create', methods=('GET', 'POST'))
@login_required # 데코레이터, 로그인한 사용자만 글을 쓸 수 있음
def create():
	if request.method == 'POST':
		title = request.form['title']
		body = request.form['body']
		error = None

		if not title:
			error = 'Title is required'
		
		if error is not None:
			flash(error)
		else:
			db = get_db()
			db.execute(
				'INSERT INTO post (title, body, author_id)'
				' VALUES (?, ?, ?)',
				(title, body, g.user['id'])
			)
			db.commit()
			return redirect(url_for('blog.index'))

	return render_template('blog/create.html')

def get_post(id, check_author=True):
	post = get_db().execute(
		'SELECT p.id, title, body, created, author_id, username'
		' FROM post p JOIN user u ON p.author_id = u.id'
		' WHERE p.id = ?',
		(id,)
	).fetchone()

	if post is None:
		abort(404, "Post id {0} doesn't exist.".format(id))
	
	if check_author and post['author_id'] != g.user['id']:
		abort(403)
	
	return post     

@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
	post = get_post(id)

	if request.method == 'POST':
		title = request.form['title']
		body = request.form['body']
		error = None

		if not title:
			error = 'Title is required.'

		if error is not None:
			flash(error)
		else:
			db = get_db()
			db.execute(
				'UPDATE post SET title = ?, body = ?'
				' WHERE id = ?',
				(title, body, id)
			)
			db.commit()
			return redirect(url_for('blog.index'))

	return render_template('blog/update.html', post=post)

@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
	get_post(id)
	db = get_db()
	db.execute('DELETE FROM post WHERE id = ?', (id,))
	db.commit()
	return redirect(url_for('blog.index'))
````



**Templates**

- file that contaion static data as well as placeholders for dynamic data
- 플라스크는 Jinja template 라이브러리 사용-
- Jinja
  - 사용자가 입력하는 < , > 같은 문자들을 안전하게 처리
  - {{ }} : will be output to the final document
  - {% %} : control flow 란 것을 알려줌, if나 for loop같은



**Base Layout**

각각의 레이아웃의 기초가 됨, 각각의 template는 아래를  extend해서 사용하거나 특정 부분을 override

````html
<!doctype html>
<title>{% block title %}{% endblock %} - Flaskr</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
<nav>
  <h1>Flaskr</h1>
  <ul>
    {% if g.user %}
      <li><span>{{ g.user['username'] }}</span>
      <li><a href="{{ url_for('auth.logout') }}">Log Out</a>
    {% else %}
      <li><a href="{{ url_for('auth.register') }}">Register</a>
      <li><a href="{{ url_for('auth.login') }}">Log In</a>
    {% endif %}
  </ul>
</nav>
<section class="content">
  <header>
    {% block header %}{% endblock %}
  </header>
    <!-- 에러메시지를 보여주기 위한 부분 -->
  {% for message in get_flashed_messages() %}
    <div class="flash">{{ message }}</div>
  {% endfor %}
  {% block content %}{% endblock %}
</section>
````



**Register**(LogIn도 유사함)

````html
<!-- base.html 을 replace -->
{% extends 'base.html' %}

{% block header %}
	<h1>{% block title %}Register{% endblock %} </h1>
{% endblock %}

{% block content %}
	<form method="post">
		<label for="username ">Username</label>
        <!-- required attr : 공백 허용 x-->
		<input name="username" id="username" required>
		<label for="password">Password</label>
		<input type="password" name="password" id="password" required>
		<input type="submit" value="Register">
	</form>
{% endblock %}
````





Make the Project Installable

setup.py - 프로젝트와 프로젝트에 속한 파일들에 대해 설명



데코레이터 쓰는 이유?

http://schoolofweb.net/blog/posts/%ED%8C%8C%EC%9D%B4%EC%8D%AC-%EB%8D%B0%EC%BD%94%EB%A0%88%EC%9D%B4%ED%84%B0-decorator/

- 기존에 만들어져 있는 코드를 수정하지 않고 wrapper함수를 이용해 여러가지 기능을 추가할 수 있음 

````python
def decorator_function(original_function):
	def wrapper_function():
		print( "{} function is not call yet".format(original_function.__name__))
		return original_function()
	return wrapper_function

@decorator_function 
def display():
	print('display1 function execute')

@decorator_function
def display_info(name, age):
	print('display_info({},{}) function execute'.format(name, age) )

# @decorator_function과 동일
#display = decorator_function(display_1)

display()
print
# wrapper함수에서 인자를 받지않으므로 오류가 발생함
display_info('ellen',24 ) 
````

````python
# wrapper 함수에 인자를 전달하기 위해 아래처럼 wrapper 함수를 수정
def decorator_function(original_function):
	def wrapper_function(*args, **kwargs):
		print( "{} function is not call yet".format(original_function.__name__))
		return original_function(*args, **kwargs)
	return wrapper_function
````