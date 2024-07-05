from __future__ import annotations
from datetime import date
from typing import List
from flask import Flask, abort, render_template, redirect, url_for, flash, request, g
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import os
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

#Email and Password
my_email = os.environ.get('EMAIL')
password = os.environ.get("PASSWORD")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'

db = SQLAlchemy(model_class=Base)
db.init_app(app)

#Gravatar setup
gravatar = Gravatar(app,size=100,rating='g',default='retro',force_default=False,force_lower=False,use_ssl=False,base_url=None)

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped["User"] = relationship(back_populates="posts")
    author_id: Mapped[int] = mapped_column(ForeignKey("user_logs.id"))
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments: Mapped[List["Comment"]] = relationship(back_populates="parent_post")


# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = "user_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    posts: Mapped[List["BlogPost"]] = relationship(back_populates="author")
    comments: Mapped[List["Comment"]] = relationship(back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment_author: Mapped["User"] = relationship(back_populates="comments")
    author_id: Mapped[int] = mapped_column(ForeignKey("user_logs.id"))
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    parent_post: Mapped["BlogPost"] = relationship(back_populates="comments")
    text: Mapped[str] = mapped_column(Text, nullable=False)

with app.app_context():
    db.create_all()

def admins(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if current_user.id != 1:
                return render_template('admin.html')
            return f(*args, **kwargs)
        except AttributeError:
            return redirect(url_for('login'))
    return decorated_function

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        same_email = db.session.execute(db.select(User).where(User.email == form.email.data)).scalars().all()
        if same_email:
            error = "You have registered with this email"
            return redirect(url_for('login', err=error))
        user_data = User(email=form.email.data, password=hashed_password, name=form.name.data)
        db.session.add(user_data)
        db.session.commit()
        login_user(user_data)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    error = request.args.get('err')
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        get_record = db.session.execute(db.select(User).where(User.email == email)).scalars().all()
        print(get_record)
        if not get_record:
            email_error = "That email is not registered"
            return render_template("login.html", form=form, error=email_error)
        for record in get_record:
            hashed_password = record.password
            check_password = check_password_hash(hashed_password, password)
            if check_password == True:
                if record.id == 1:
                    login_user(record)
                    return redirect(url_for('get_all_posts', user='admin'))
                else:
                    login_user(record)
                    return redirect(url_for('get_all_posts'))
            else:
                password_error = "The password was incorrect"
                return render_template("login.html", form=form, error=password_error)
    return render_template("login.html", form=form, error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    user = db.session.execute(db.select(User)).scalars().all()
    admin = request.args.get('user')
    return render_template("index.html", all_posts=posts, admin=admin, user=user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        comment = Comment(text=form.comment.data, author_id=current_user.id, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_section = db.session.execute(db.select(Comment).where(Comment.post_id == post_id)).scalars().all()
    admin = request.args.get('user')
    return render_template("post.html", post=requested_post, form=form, admin=admin, comments = comment_section)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admins
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admins
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admins
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/contact", methods=['POST', 'GET'])
def receive_data():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    message = request.form['message']
    print(f"Name:{name}, Email:{email}, Phone:{phone}, Message:{message}")
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_email, password=password)
        connection.sendmail(
            from_addr=my_email,
            to_addrs=my_email,
            msg=f"Subject:Blog Contact Form\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
        )
    return render_template('contact.html', prompt='Successfully sent Message')

@login_manager.unauthorized_handler
def unauthorized():
    # do stuff
    return render_template('admin.html')

if __name__ == "__main__":
    app.run(debug=False, port=5002)
