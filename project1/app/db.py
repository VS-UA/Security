import hashlib
import sqlite3

# from utils import Comm
from flask import Request


class DBManager:
    """
    Handles all the database logic
    """

    def __init__(self):
        self.__con = sqlite3.connect("db.db", check_same_thread=False)
        self.__cur = self.__con.cursor()

    def __run(self, query):
        """
        Executes a query and returns it's result
        """

        res = self.__cur.execute(query).fetchall()
        self.__con.commit()

        return res

    def comment(self, text, author):
        """
        Adds a post to the database.
        Posts added by this method are root posts, they are not replies.
        """
        # TODO: add integrity check for author
        self.__run(f"INSERT INTO comm (author, txt) VALUES (\'{author}\', \'{text}\')")

        return self.__run(f"SELECT id FROM comm ORDER BY id DESC LIMIT 1")[0][0]

    def reply(self, parent, text, author):
        """
        Adds a reply containing text to the comment parent
        """
        self.__run(f"INSERT INTO comm (parent, author, txt) values (\'{parent}\', \'{author}\', \'{text}\')")

        return self.__run(f"SELECT id FROM comm ORDER BY id DESC LIMIT 1")[0][0]

    def get_replies(self, com_id, mapper=None):
        reps = self.__run(f"SELECT id FROM comm WHERE parent = \'{com_id}\'")

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
        data = self.__run(f"SELECT id, txt, parent, author FROM comm WHERE id==\'{id}\'")[0]

        ret = Comm(data[0], data[1], data[2], data[3])
        return ret

    def get_text(self, id):
        return self.__run(f"SELECT txt FROM comm WHERE id==\'{id}\'")[0]

    @staticmethod
    def __hash(password):
        return hashlib.sha1(password.encode()).hexdigest()

    def already_registered(self, user):
        usrs = self.__run(f"SELECT * FROM usr WHERE username='{user}'")

        return len(usrs) != 0

    def register(self, usr, password, mail):
        password_hash = self.__hash(password)
        self.__run(f"INSERT INTO usr (username, password_hash, email) VALUES ('{usr}', '{password_hash}', '{mail}')")

    def delete_person(self,username):
        self.__run(f"""DELETE FROM usr WHERE EXISTS(SELECT * FROM usr WHERE username='{username}')""")
        
    def set_admin(self, username, password, mail):
        if password is None and mail is None:
            self.__run(f"UPDATE usr SET isadmin=1 WHERE username=\'{username}\'")
            return

        password_hash = self.__hash(password)
        self.__run(f"""DELETE FROM usr WHERE EXISTS(SELECT * FROM usr WHERE username='{username}')""")
        self.__run(f"""INSERT INTO usr (username, password_hash, email, isadmin) VALUES ('{username}', '{password_hash}', '{mail}', '{1}')""")

    def login(self, username, password):
        return len(self.__run(f"SELECT * FROM usr WHERE username='{username}' AND password_hash='{self.__hash(password)}'")) != 0

    def get_logged_in_user(self, request: Request):
        if 'username' in request.cookies and 'password' in request.cookies:
            username = request.cookies['username']
            password = request.cookies['password']

            result = self.__run(f"SELECT * FROM usr WHERE username='{username}' AND password_hash='{password}'")
            if len(result) != 0:
                return result

        return None

    def is_admin(self, username):
        return len(self.__run(f"SELECT * FROM usr WHERE username='{username}' AND isadmin='{1}'")) != 0

    def get_email(self, username):
        return self.__run(f"SELECT email FROM usr WHERE username='{username}'")

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

    def delete_db(self):
        db.create(reset=True)

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


db = DBManager()


def stuff():
    db.create(reset=True)

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

    db.register("user", "1234", "user@company.com")

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
