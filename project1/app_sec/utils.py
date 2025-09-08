from flask import Request

from db import DBManager



def compose_replies(db_man: DBManager, parent: int) -> str:
    """
    Composes the HTML string for the replies
    """
    lst = db_man.get_replies(parent)
