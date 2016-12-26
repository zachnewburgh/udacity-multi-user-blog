import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2
import json

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Secret Code for Cookies

secret = 'secretcodehere'

# Template Rendering


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# Cookie Settings

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Basic Blog Functionality: template rendering and user authentication.

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# Password Authentication

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# User Model

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# Blog Key

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Post Model

class Post(db.Model):
    author = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    likes = db.ListProperty(str, indexed=False, default=[])
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=blog_key())

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# Comment Model

class Comment(db.Model):
    content = db.TextProperty(required=True)
    post = db.ReferenceProperty(Post, collection_name='comments')
    author = db.ReferenceProperty(User, collection_name='comments')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=blog_key())


# Blog's Homepage:
# displays posts and handles 'like' functionality for each post.

class BlogFront(BlogHandler):
    def get(self):
        if self.user:
            posts = Post.all().order('-created')
            self.render('front.html', posts=posts)
        else:
            self.redirect('/login')

    def post(self):
        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)
        author = post.author
        user = self.user.name

        like = self.request.get('like')

        if author == user:
            posts = Post.all().order('-created')
            error = "You can't like/unlike your own posts!"
            self.render('front.html', posts=posts, error=error)
        elif like == "like" and (user not in post.likes):
            post.likes.append(user)
            post.put()
            self.redirect('/')
        elif author in post.likes:
            post.likes.remove(user)
            post.put()
            self.redirect('/')
        else:
            self.redirect('/')


# Post's Show Page:
# displays post and handles comment functionality for each post.

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

    def post(self, post_id):
        post = Post.by_id(int(post_id))
        author = self.user
        content = self.request.get('content')

        c = Comment(parent=blog_key(),
                    content=content,
                    post=post,
                    author=author)
        c.put()
        self.redirect('/posts/%s' % str(post_id))


# Post Create Page: render form and create a post if the user is authenticated.

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        author = self.request.get('author')
        subject = self.request.get('subject')
        content = self.request.get('content')

        if author and subject and content:
            p = Post(parent=blog_key(),
                     author=author,
                     subject=subject,
                     content=content)
            p.put()
            self.redirect('/posts/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        author=author,
                        subject=subject,
                        content=content,
                        error=error)


# Post's Edit Page:
# render form and edit post
# only if the post belongs to the user.

class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user.name == post.author:
            self.render("editpost.html", post=post)
        else:
            posts = Post.all().order('-created')
            error = "You can only edit your own posts!"
            self.render('front.html', posts=posts, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)

        author = p.author
        subject = self.request.get('subject')
        content = self.request.get('content')

        if self.user.name == p.author:
            if subject and content:
                p.subject = subject
                p.content = content
                p.put()
                self.redirect('/posts/%s' % str(p.key().id()))
            else:
                error = "subject and content, please!"
                self.render("editpost.html", post=p, error=error)
        else:
            self.redirect('/')


# Post's Delete Page:
# renders a form to confirm the deletion of a post
# only if the post belongs to the user.

class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user.name == post.author:
            self.render("deletepost.html", post=post)
        else:
            posts = Post.all().order('-created')
            error = "You can only delete your own posts!"
            self.render('front.html', posts=posts, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)

        delete = self.request.get('delete')
        if self.user.name == p.author:
            if delete == "Yes":
                p.delete()
                self.redirect('/')
            else:
                self.redirect('/')
        else:
            self.redirect('/')


# Comment's Edit Page:
# renders form and edit post
# only if the post belongs to the user.

class EditComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)

        if self.user.name == comment.author.name:
            self.render("editcomment.html", comment=comment)
        else:
            posts = Post.all().order('-created')
            error = "You can only edit your own comments!"
            self.render('front.html', posts=posts, error=error)

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        c = db.get(key)

        content = self.request.get('content')
        if self.user.name == c.author.name:
            if content:
                c.content = content
                c.put()
                self.redirect('/posts/%s' % str(c.post.key().id()))
            else:
                error = "content, please!"
                self.render("editcomment.html", comment=c, error=error)
        else:
            self.redirect('/posts/%s' % str(c.post.key().id()))


# Comment's Delete Page:
# renders a form to confirm the deletion of a post
# only if the post belongs to the user.

class DeleteComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)

        if self.user.name == comment.author.name:
            self.render("deletecomment.html", comment=comment)
        else:
            posts = Post.all().order('-created')
            error = "You can only delete your own comments!"
            self.render('front.html', posts=posts, error=error)

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        c = db.get(key)
        post = c.post

        delete = self.request.get('delete')
        if self.user.name == c.author.name:
            if delete == "Yes":
                c.delete()
                self.redirect('/posts/%s' % str(post.key().id()))
            else:
                self.redirect('/posts/%s' % str(post.key().id()))
        else:
            self.redirect('/posts/%s' % str(post.key().id()))


# Signup Authentication Helper Functions

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# User Signup Page

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# Allow user registration if user does not already exist.

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


# User Login Page

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


# User Logout

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')


# Welcome Page

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/register')


app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/posts/([0-9]+)', PostPage),
                               ('/posts/new', NewPost),
                               ('/posts/edit/([0-9]+)', EditPost),
                               ('/posts/delete/([0-9]+)', DeletePost),
                               ('/comments/edit/([0-9]+)', EditComment),
                               ('/comments/delete/([0-9]+)', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
