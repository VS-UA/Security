import hashlib
import re

from flask import Flask, redirect, url_for, request, render_template, make_response
from flask_restful import Api

import db as database


app = Flask(__name__)
api = Api(app)
db = database.db


@app.route("/style.css")
def style():
    with open("./style.css", 'r') as s:
        return s.read(), 200


@app.route("/")
def main_page():
    """
    Serves the main page, with all the posts
    """

    # print(f"!!! {db.get_all_roots()}")
    posts = "".join([db.build_comment(com).to_html(db) for com in db.get_all_roots()])

    with open("./index.html", 'r') as page:
        content = page.read().format(posts=posts)

    return render_template("index.html", content=content)

@app.route("/profile/<username>", methods=['GET', 'POST'])
def profile(username):
    """
    Serves the profile page
    """
    if request.method == 'GET':
        success = True
        email = None
        email = db.get_email(username)
        if username == None and email == None:
            success = False
        if db.is_admin(username) == False:
            admin = False
        else:
            admin = True
        comments = db.get_comments(username)
        if success == True:
            return render_template('profile.html', username=username, email=email, isadmin=admin, comments=comments)
        else:
            return render_template('login.html')
    else:
        return redirect(url_for("main_page"))

@app.route("/comment", methods=['GET', 'POST'])
def comment():
    if request.method == 'GET':
        print(db.get_logged_in_user(request))
        if db.get_logged_in_user(request) is None:
            return redirect(url_for("main_page"))

        with open("./comment.html", 'r') as page:
            return page.read(), 200
    else:
        result = db.get_logged_in_user(request)
        if result is None:
            return redirect("/")

        com = request.form['text']
        parent = request.args.get('id')
        author = result[0][0]

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


@app.route("/register", methods=['POST', 'GET'])
def register():
    """
    Serves the register page
    """
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        username_error = password_error = email_error = ""
        success = True
        if username == "":
            username_error = "Username cannot be empty"
            success = False
        if password == "":
            password_error = "Password cannot be empty"
            success = False
        if email == "":
            email_error = "E-mail cannot be empty"
            success = False

        if not success:
            return render_template('register.html', invalid_username=username_error, invalid_email=email_error,
                                   invalid_password=password_error, failed=True)

        if db.already_registered(username):
            username_error = "Username already taken"
            return render_template('register.html', invalid_username=username_error, invalid_email=email_error,
                                   invalid_password=password_error, failed=True)
        else:
            db.register(username, password, email)
            return redirect(url_for('login'))

    else:
        return render_template('register.html')


@app.route("/logout", methods=['POST', 'GET'])
def logout():
    resp = make_response(redirect(url_for('login')))
    if db.get_logged_in_user(request) is not None:
        resp.delete_cookie('username')
        resp.delete_cookie('password')
    return resp


@app.route("/login", methods=['POST', 'GET'])
def login():
    """
    Serves the login page
    """
    if db.get_logged_in_user(request) is not None:
        return redirect("/")
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.sha1(password.encode()).hexdigest()

        username_error = password_error = ""
        success = True

        if username == "":
            username_error = "Username cannot be empty"
            success = False
        if password == "":
            password_error = "Password cannot be empty"
            success = False

        if not success:
            return render_template('login.html', invalid_username=username_error, invalid_password=password_error,
                                   failed=True)

        if db.login(username, password):
            response = make_response(
                render_template('login.html', invalid_username=username_error, invalid_password=password_error,
                                success=True))
            response.set_cookie('username', username, secure=False, httponly=False)
            response.set_cookie('password', password_hash, secure=False, httponly=False)
            return response
        else:
            return render_template('login.html', invalid_username=username_error, invalid_password=password_error,
                                   failed=True)
    else:
        return render_template('login.html')

@app.route("/admin", methods=['POST', 'GET'])
def admin():
    """
    Serves the new admin page
    form with username and selection for add admin/remove user
    """
    if request.method == "POST":
        if request.form["opt"] == "adm":
            db.set_admin(request.form["user"], None, None)
        else:
            db.delete_person(request.form["user"])

        return redirect(url_for("admin"))
    else:
        if db.get_logged_in_user(request) is None:
            return redirect(url_for("main_page"))
        with open("admin.html", 'r') as adm:
            return adm.read(), 200

# @app.route("/admin", methods=['POST', 'GET'])
# def admin():
#     """
#     Serves the admin page
#     """
#     if request.method == 'POST':
#         if db.get_logged_in_user(request) is None:
#             return redirect(url_for("main_page"))
#
#         print(request.form)
#         if "Submit" in request.form:
#             username = request.form['username']
#             email = request.form['email']
#             password = request.form['password']
#
#             username_error = password_error = email_error = ""
#             success = True
#             if username == "":
#                 username_error = "Username cannot be empty"
#                 success = False
#             if password == "":
#                 password_error = "Password cannot be empty"
#                 success = False
#             if email == "":
#                 email_error = "E-mail cannot be empty"
#                 success = False
#
#             if not success:
#                 return render_template('admin.html', invalid_username=username_error, invalid_email=email_error,
#                                        invalid_password=password_error, failed=True)
#             if db.already_registered(username):
#                 username_error = "Username already taken"
#                 return render_template('admin.html', invalid_username=username_error, invalid_email=email_error,
#                                        invalid_password=password_error, failed=True)
#             else:
#                 db.set_admin(username, password, email)
#                 return redirect(url_for('admin'))
#
#         elif "Delete person":
#             username = request.form['username']
#             username_error = ""
#             success = True
#             if username == "":
#                 username_error = "Username cannot be empty"
#                 success = False
#             if not success:
#                 return render_template('admin.html', invalid_username=username_error, failed=True)
#             if not db.already_registered(username):
#                 username_error = "Username already deleted"
#                 return render_template('admin.html', invalid_username=username_error, failed=True)
#             else:
#                 db.delete_person(username)
#                 return redirect(url_for('admin'))
#
#         elif "Reset db" in request.form:
#             db.delete_db()
#             return redirect(url_for('admin'))
#     else:
#         if db.get_logged_in_user(request) is None:
#             return redirect(url_for("main_page"))
#         return render_template('admin.html')


if __name__ == '__main__':
    database.stuff()
    app.run(debug=False, host='0.0.0.0', port=80)
