import hashlib
import sqlite3

from bleach import clean
# from utils import Comm
from flask import Request

# https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
# https://bleach.readthedocs.io/en/latest/


class DBManager:
    """
    Handles all the database logic
    """

    def __init__(self):
        self.__con = sqlite3.connect("db.db", check_same_thread=False)
        self.__cur = self.__con.cursor()

    # def __clean(self, text):
    #     & --> &amp;
    #     < --> &lt;
    #     > --> &gt;
    #     " --> &quot;
    #     ' --> &#x27;

    def __run(self, query, parameters=()):
        """
        Executes a query and returns it's result
        """
        res = self.__cur.execute(query, parameters).fetchall()
        self.__con.commit()

        return res

    def comment(self, text, author):
        """
        Adds a post to the database.
        Posts added by this method are root posts, they are not replies.
        """
        # TODO: add integrity check for author
        print(text)
        self.__run("INSERT INTO comm (author, txt) VALUES (?, ?)", (clean(author), clean(text)))

        return self.__run("SELECT id FROM comm ORDER BY id DESC LIMIT 1")[0][0]

    def reply(self, parent, text, author):
        """
        Adds a reply containing text to the comment parent
        """
        self.__run("INSERT INTO comm (txt, parent, author) values (?, ?, ?)",
                   (clean(text), clean(str(parent)), clean(author)))

        return self.__run("SELECT id FROM comm ORDER BY id DESC LIMIT 1")[0][0]

    def get_replies(self, com_id, mapper=None):
        reps = self.__run("SELECT id FROM comm WHERE parent = ?", (clean(str(com_id)),))

        children = [
            v[0] if mapper is None else mapper(v[0])
            for v in reps]

        if not children:
            return []

        reps = [r[0] for r in reps]
        return children + [self.get_replies(c, mapper=mapper) for c in reps]

    def get_all_roots(self):
        return [v[0] for v in self.__run("SELECT id FROM comm WHERE parent IS NULL")]

    def build_comment(self, id):
        """
        Builds a Comm object from id
        """
        data = self.__run("SELECT id, txt, parent, author FROM comm WHERE id==?", (clean(str(id)),))[0]

        ret = Comm(data[0], data[1], data[2], data[3])
        return ret

    def get_user(self, user):
        usrs = self.__run("SELECT * FROM usr WHERE username=?", (clean(user),))
        if usrs is None or len(usrs) != 1:
            return None
        else:
            return usrs[0]

    def get_user_data(self, user):
        usrs = self.__run("SELECT * FROM usr WHERE username=?", (clean(user),))
        if usrs is None or len(usrs) != 1:
            return None
        else:
            return {"username": usrs[0][0], "password_hash": usrs[0][1], "password": usrs[0][2], "seed": usrs[0][3]}

    def get_admin(self, user):
        usrs = self.__run("SELECT * FROM usr WHERE username=? and isadmin=1", (clean(user),))
        if usrs is None or len(usrs) != 1:
            return None
        else:
            return usrs[0]
    
    def is_admin(self, username):
        return len(self.__run(f"SELECT * FROM usr WHERE username='{username}' AND isadmin='{1}'")) != 0

    def get_email(self, username):
        if len(self.__run(f"SELECT email FROM usr WHERE username='{username}'")) != 0:
            return self.__run(f"SELECT email FROM usr WHERE username='{username}'")
        else:
            return None

    def can_view_profile(self, username, email):
        if db.is_admin(username) == True or email == self.__run(f"SELECT email FROM usr WHERE username='{username}'"):
            return True
        return False

    def get_comments(self, username):
        comments = []
        ids = []
        while True:
            comment = self.__run(f"SELECT txt FROM comm WHERE author='{username}'")
            id = self.__run(f"SELECT id FROM comm WHERE txt='{comment}'")
            if id in ids:
                break
            else:
                ids.append(id)
                comments.append(comment)
        return comments

    def set_admin(self, username, password, mail):
        if password is None and mail is None:
            self.__run("UPDATE usr SET isadmin=1 WHERE username=?", (username,))
            return

        self.__run("DELETE FROM usr WHERE EXISTS(SELECT * FROM usr WHERE username=?)", (username,))
        self.__run("INSERT INTO usr (username, password_hash, email, isadmin) VALUES (?, ?, ?, 1)",
                   (username, password, mail))

    # def create_user(self, user: str, password_hash: str, mail: str):
    #     self.__run("INSERT INTO usr (username, password_hash, email) VALUES (?, ?, ?)",
    #                (clean(user), clean(password_hash), clean(mail)))

    def create_user(self, user: str, password_hash: str, password:str, seed:bytes, mail: str):
        self.__run("INSERT INTO usr (username, password_hash, password, seed, email) VALUES (?, ?, ?, ?, ?)",
                   (clean(user), clean(password_hash), clean(password), memoryview(seed), clean(mail)))

    def create_admin(self, username, password, mail):
        password_hash = self.__hash(password)
        self.__run(f"DELETE FROM usr WHERE EXISTS(SELECT * FROM usr WHERE username=?", (clean(username),))
        self.__run("INSERT INTO usr (username, password_hash, email,isadmin) VALUES (?, ?, ?, ?)",
                   (clean(username), clean(password_hash), clean(mail), 1))

    def delete_person(self, user):
        self.__run(f"DELETE FROM usr WHERE EXISTS(SELECT * FROM usr WHERE username=?"), (clean(user))

    def delete_db(self):
        self.__run("DROP TABLE IF EXISTS comm")
        self.__run(
            """
            CREATE TABLE IF NOT EXISTS comm (
                txt text NOT NULL,
                parent INTEGER,
                id INTEGER PRIMARY KEY AUTOINCREMENT
            );
            """
        )

    def create(self, reset=False):
        """
        Creates the tables if they don't exist
        The reset flag is a debug flag to reset the database when the app turns on
        """
        if reset:
            self.__run("DROP TABLE IF EXISTS comm")
            self.__run("DROP TABLE IF EXISTS usr")

        self.__run(
            """
            CREATE TABLE IF NOT EXISTS comm (
                txt text NOT NULL,
                parent INTEGER,
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author text NOT NULL 
            );
            """
        )

        self.__run(
            """
            CREATE TABLE IF NOT EXISTS usr (
                username text NOT NULL PRIMARY KEY,
                password_hash text NOT NULL,
                password text NOT NULL,
                seed text NOT NULL,
                email text NOT NULL,
                isadmin INTEGER NOT NULL CHECK (isadmin IN (0, 1)) DEFAULT 0
            );
            """
        )


class Comm:
    """
    Defines a comment
    """

    def __init__(self, id, text, parent, author):
        self.__text = text
        self.__id = id
        self.__parent = parent
        self.__author = author

    def to_html(self, db_man: DBManager):
        data = db_man.get_replies(self.__id)
        with open("post.html", 'r') as t:
            template = t.read()

        def process(l: list):
            div = int(len(l) / 2)
            if div == 0:
                return ""

            res = ""
            for i in range(div):
                c = db.build_comment(l[i])
                res += template.format(replies=process(l[i + div]), text=c.__text, author=c.__author, id=c.__id)

            return res

        return template.format(replies=process(data), text=self.__text, author=self.__author, id=self.__id)

    def __str__(self):
        with open("post.html", 'r') as f:
            return f.read().format(text=self.__text)

    def get_text(self):
        return self.__text

    def __str__(self):
        with open("post.html", 'r') as f:
            return f.read().format(text=self.__text)

    def get_text(self):
        return self.__text


db = DBManager()


def stuff():
    db.create(reset=False)

    a0 = db.comment("0", "Joe")

    a1 = db.comment("1", "Deez")

    a2 = db.reply(a1, "1-1", "Mama")
    a3 = db.reply(a1, "1-2", "Moe")
    a4 = db.reply(a1, "1-3", "Ligma")

    a5 = db.reply(a2, "2-1", "Hugh")
    a6 = db.reply(a2, "2-2", "Updog")
    a7 = db.reply(a3, "3-1", "Candice")

    b1 = db.comment("<script>alert(\"Vulnerable to XSS!\")</script>", "H3k3r_xXx")
    #   self.__run(f"INSERT INTO comm (txt) VALUES (\'{text}\')")
    b2 = db.comment("VULNERABLE TO SQL INJECTION! ' || (SELECT id FROM comm)); -- //", "RoboKiller_42069")

    return a1


if __name__ == '__main__':
    # print(db.get_replies(a1))
    # print("END CALL")
    # print(db.get_replies(a1, mapper=lambda s: f"!{s}"))

    a = stuff()

    with open("index.html", 'r') as page:
        print(page.read().format(posts=db.build_comment(a).to_html(db)))
        print(db.get_replies(a))
        print(db.get_replies(a, lambda x: f"!{x}"))  # db.build_comment(a).get_text()))
