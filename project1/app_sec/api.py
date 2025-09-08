import re
import secrets

from flask import Flask, redirect, url_for, session, request, render_template, make_response
from flask_restful import Api

import db as database
import auth as auth

app = Flask(__name__)
api = Api(app)
db = database.db
auth = auth.Auth(db)

app.secret_key = secrets.token_hex()


@app.before_request
def before_request():
    auth.renew_session(session)


@app.route("/style.css")
def style():
    with open("./style.css", 'r') as s:
        return s.read(), 200


@app.route("/")
def main_page():
    """
    Serves the main page, with all the posts
    """
    posts = "".join([db.build_comment(com).to_html(db) for com in db.get_all_roots()])

    with open("./index.html", 'r') as page:
        content = page.read().format(posts=posts)

    return render_template("index.html", content=content)

@app.route("/verifcation", methods=['GET', 'POST'])
def verification():
    """
    Serves the verification for the profile page
    """
    if request.method == 'POST' and 'username' in request.form and 'email' in request.form:
        if auth.get_logged_in_user(request) is None or auth.get_logged_in_admin(request) is None:
            return redirect("/")

        email = request.form['email']
        username = request.form['username']

        if not auth.is_username_valid(username) or not auth.is_email_valid(email):
            return redirect(url_for("main_page"))
        if db.can_view_profile(username, email) == True:
            if db.is_admin(username) == False:
                admin = False
            else:
                admin = True
            comments = db.get_comments(username)
            return render_template('profile.html', username=username, email= email, isadmin=admin, comments=comments)
        else:
            return redirect(url_for("main_page"))
    else:
        if auth.get_logged_in_user(request) is None:
            username = auth.get_logged_in_admin(session)
        elif auth.get_logged_in_admin(request) is None:
            username = auth.get_logged_in_user(session)
        else:
            return redirect("/")
        email = db.get_email(username)
        if auth.is_username_valid(username) and auth.is_email_valid(email):
            success = False
        if db.is_admin(username) == False:
            admin = False
        else:
            admin = True
        comments = db.get_comments(username)
        if success == True:
            return render_template('profile.html', username=username, email=email, isadmin=admin, comments=comments, success=success)
        else:
            return render_template('login.html')

@app.route("/profile", methods=['GET', 'POST'])
def profile():
    """
    Serves the profile page
    """
    if request.method == 'GET':
        if auth.get_logged_in_user(request) is None:
            username = auth.get_logged_in_admin(session)
        elif auth.get_logged_in_admin(request) is None:
            username = auth.get_logged_in_user(session)
        else:
            return redirect("/")
        email = db.get_email(username)
        if auth.is_username_valid(username) and auth.is_email_valid(email):
            success = False
        if db.is_admin(username) == False:
            admin = False
        else:
            admin = True
        comments = db.get_comments(username)
        if success == True:
            return render_template('profile.html', username=username, email=email, isadmin=admin, comments=comments, success=success)
        else:
            return render_template('login.html')
    else:
        if auth.get_logged_in_user(request) is None or auth.get_logged_in_admin(request) is None:
            return redirect("/")

        email = request.form['email']
        username = request.form['username']

        if not auth.is_username_valid(username) or not auth.is_email_valid(email):
            return redirect(url_for("main_page"))
        if db.can_view_profile(username, email) == True:
            if db.is_admin(username) == False:
                admin = False
            else:
                admin = True
            comments = db.get_comments(username)
            return render_template('profile.html', username=username, email= email, isadmin=admin, comments=comments)
        else:
            return redirect(url_for("main_page"))

@app.route("/comment", methods=['GET', 'POST'])
def comment():
    if request.method == 'GET':
        print(auth.get_logged_in_user(session))
        if auth.get_logged_in_user(session) is None:
            return redirect(url_for("main_page"))

        with open("./comment.html", 'r') as page:
            return page.read(), 200
    else:
        if auth.get_logged_in_user(session) is None:
            return redirect("/")

        com = request.form['text']
        parent = request.args.get('id')
        # author = request.cookies.get('username')
        author = auth.get_logged_in_user(session)[0]

        print(f"{com}\n{parent}\n{author}")

        if author is None:
            redirect(url_for("main_page"))

        if parent is None:
            print("new comm")
            db.comment(com, author)
        else:
            print("reply")
            db.reply(parent, com, author)

        return redirect(url_for("main_page"))


@app.route("/logout", methods=['POST', 'GET'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route("/register", methods=['POST', 'GET'])
def register():
    """
    Serves the register page\n
    The only reason we disclose if a particullar user already exists is because an attacker would easily realize when that's the case i.e.(password and e-mail both meet the requirements)
    """
    if auth.get_logged_in_user(session) is not None:
        return redirect("/")
    elif request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        username_error = password_error = email_error = ""
        success = True
        if not auth.is_username_valid(username):
            username_error = "Invalid username! Please check the requirements again."
            success = False
        if not auth.is_password_valid(password):
            password_error = "Invalid password! Please check the requirements again."
            success = False
        if not auth.is_email_valid(email):
            email_error = "Invalid e-mail! Please check the requirements again."
            success = False

        if not success:
            return render_template('register.html', invalid_username=username_error, invalid_email=email_error,
                                   invalid_password=password_error, failed=True)

        if auth.does_user_exist(username):
            username_error = "Username already taken! Please choose a different one."
            return render_template('register.html', invalid_username=username_error, invalid_email=email_error,
                                   invalid_password=password_error, failed=True)
        elif auth.register(username, password, email):
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route("/login", methods=['POST', 'GET'])
def login():
    """
    Serves the login page\n
    We don't disclose why a login failed. we just say it did. doing otherwise would give an attacker valuable information
    """
    if auth.get_logged_in_user(session) is not None:
        return redirect("/")
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:

        username = request.form['username']
        password = request.form['password']

        if not auth.is_username_valid(username) or not auth.is_password_valid(password):
            return render_template('login.html', failed="Login Failed!")

        if auth.login(username, password, session):
            return render_template('login.html', success="Success! You're logged in!")
        else:
            return render_template('login.html', failed="Login Failed!")

    else:
        return render_template('login.html')

@app.route("/admin", methods=['POST', 'GET'])
def admin():
    """
    Serves the admin page
    """
    print(request.form)

    if request.method == "POST":
        if auth.get_logged_in_admin(session) is None:
            return redirect(url_for("main_page"))

        if request.form["opt"] == "adm":
            db.set_admin(request.form["user"], None, None)
        elif request.form["opt"] == "del":
            db.delete_person(request.form["user"])

        return redirect(url_for("admin"))
    else:
        if auth.get_logged_in_admin(session) is None:
            return redirect(url_for("main_page"))
        with open("admin.html", 'r') as adm:
            return adm.read(), 200


# @app.route("/admin", methods=['POST', 'GET'])
# def admin():
#    """
#    Serves the admin page
#    """
#    if auth.get_logged_in_admin(session) is  None:
#        return redirect("/")
#    if request.method == 'POST':
#        if db.get_logged_in_user(request) is None:
#            return redirect(url_for("main_page"))
#        if "Submit" in request.form:
#            username = request.form['username']
#            email = request.form['email']
#            password = request.form['password']
#
#            username_error = password_error = email_error = ""
#            success = True
#            if not auth.is_username_valid(username):
#                username_error = "Invalid username! Please check the requirements again."
#                success = False
#            if not auth.is_password_valid(password):
#                password_error = "Invalid password! Please check the requirements again."
#                success = False
#            if not auth.is_email_valid(email):
#                email_error = "Invalid e-mail! Please check the requirements again."
#                success = False
#
#            if not success:
#                return render_template('admin.html', invalid_username=username_error, invalid_email=email_error,
#                                       invalid_password=password_error, failed=True)
#            
#            if auth.does_user_exist(username):  
#                username_error = "Username already taken"
#                return render_template('admin.html', invalid_username=username_error, invalid_email=email_error,
#                                       invalid_password=password_error, failed=True)
#            elif auth.register_admin(username, password, email):
#                return redirect(url_for('admin'))
#
#        elif "Delete person":
#            username = request.form['username']
#            username_error = ""
#            success = True
#            if not auth.is_username_valid(username):
#                username_error = "Invalid username! Please check the requirements again."
#                success = False
#            if not success:
#                return render_template('admin.html', invalid_username=username_error, failed=True)
#            if not auth.does_user_exist(username):
#                username_error = "Username already deleted"
#                return render_template('admin.html', invalid_username=username_error, failed=True)
#            else:
#                auth.delete_person(username)
#                return redirect(url_for('admin'))
#
#        elif "Reset db" in request.form:
#            auth.delete_db()
#            return redirect(url_for('admin'))
#    else:
#        return render_template('admin.html')


if __name__ == '__main__':
    database.stuff()
    app.run(debug=False, host='0.0.0.0', port=80)
    app.config.update(
        # SESSION_COOKIE_SECURE=True, uncomment this when we setup https
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
    )
