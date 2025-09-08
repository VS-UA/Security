import bcrypt
import re

from datetime import datetime, timedelta
from flask.sessions import SessionMixin
from db import DBManager


class Auth:
    def __init__(self, db: DBManager):
        self.db = db

    def __hash(self, password: str):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def is_username_valid(self, username: str):
        if username == None or username == "" or len(username) < 8:
            return False
        if re.fullmatch(r"^[a-zA-Z0-9_]+$", username):
            return True
        else:
            return False

    def is_password_valid(self, password: str):
        if password == None or password == "":
            return False
        return len(password) >= 12 and len(re.findall("[a-z]", password)) > 0 and len(
            re.findall("[A-Z]", password)) > 0 and len(re.findall("[1-9]", password)) > 0

    # https://emailregex.com/
    def is_email_valid(self, email: str):
        if email == None or email == "":
            return False
        if re.fullmatch(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
            return True
        else:
            return False

    def register(self, usr: str, password: str, mail: str):
        if self.is_username_valid(usr) and self.is_password_valid(password) and self.is_email_valid(mail):
            password_hash = self.__hash(password)
            if self.db.get_user(usr) is not None:
                return False
            self.db.create_user(usr, password_hash.decode(), mail)
            return True
        else:
            return False

    def register_admin(self, usr: str, password: str, mail: str):
        if self.is_username_valid(usr) and self.is_password_valid(password) and self.is_email_valid(mail):
            password_hash = self.__hash(password)

            self.db.create_admin(usr, password_hash.decode(), mail)
            return True
        else:
            return False

    def delete_person(self, usr: str):
        if self.is_username_valid(usr):
            if self.db.get_user(usr) is None:
                return False
            self.db.delete_person(usr)
            return True
        else:
            return False

    def login(self, username: str, password: str, session: SessionMixin):
        if self.is_username_valid(username) and self.is_password_valid(password):
            result = self.db.get_user(username)
            if result is None:
                return False
            else:
                hash = result[1]
                if bcrypt.checkpw(password.encode(), hash.encode()):
                    self.session_init(username, session)
                    return True
        return False

    def logout(self, session: SessionMixin):
        session.clear()

    def delete_db(self, session: SessionMixin):
        self.db.delete_db()

    def does_user_exist(self, username: str):
        if not self.is_username_valid(username) or self.db.get_user(username) is None:
            return False
        return True

    def get_logged_in_user(self, session: SessionMixin):
        if 'username' in session and 'expires-at' in session:
            username = session.get('username')
            if self.is_username_valid(username) and not self.has_session_expired(session):
                user = self.db.get_user(username)
                if user is None:
                    session.clear()
                return user
            else:
                session.clear()
                return None
        return None

    def get_logged_in_admin(self, session: SessionMixin):
        if 'username' in session and 'expires-at' in session:
            username = session.get('username')
            if self.is_username_valid(username) and not self.has_session_expired(session):
                user = self.db.get_admin(username)
                if user is None:
                    session.clear()
                return user
            else:
                session.clear()
                return None
        return None

    # don't touch time stuff or bad things will happen
    # TypeError: can't compare offset-naive and offset-aware datetimes
    def has_session_expired(self, session: SessionMixin):
        if 'expires-at' in session:
            return datetime.utcnow().timestamp() > session['expires-at']

    def session_init(self, username: str, session: SessionMixin):
        if self.is_username_valid(username):
            session["username"] = username
            session['expires-at'] = (datetime.utcnow() + timedelta(seconds=300)).timestamp()

    def renew_session(self, session: SessionMixin):
        if self.get_logged_in_user(session):
            session['expires-at'] = (datetime.utcnow() + timedelta(seconds=300)).timestamp()
