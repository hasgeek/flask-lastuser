# -*- coding: utf-8 -*-
"""
    flaskext.lastuser.sqlalchemy
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    SQLAlchemy extensions for flask-lastuser.

    :copyright: (c) 2011 by HasGeek Media LLP.
    :license: BSD, see LICENSE for more details.
"""
from __future__ import absolute_import

__all__ = ['UserBase', 'UserManager']

from flask import g, session
from sqlalchemy import func, Column, Integer, String, DateTime, Unicode


class UserBase(object):
    """
    Base class for user definition.
    """
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    userid = Column(String(22), unique=True, nullable=False)
    username = Column(Unicode(80), unique=True, nullable=True) # Usernames are optional
    fullname = Column(Unicode(80), default='', nullable=False)
    email = Column(Unicode(80), unique=True, nullable=True) # We may not get an email address


class UserManager(object):
    """
    User manager that automatically loads the current user's object from the database.
    """
    def __init__(self, db, usermodel):
        self.db = db
        self.usermodel = usermodel

    def before_request(self):
        # TODO: How do we cache this? Connect to a cache manager
        if g.lastuserinfo:
            user = self.usermodel.query.filter_by(userid=g.lastuserinfo.userid).first()
            if user is None:
                user = self.usermodel(userid=g.lastuserinfo.userid)
                user.username = g.lastuserinfo.username
                user.fullname = g.lastuserinfo.fullname
                user.email = g.lastuserinfo.email or None
                self.db.session.add(user)
            else:
                for attr in ['username', 'fullname', 'email']:
                    if not hasattr(user, attr):
                        setattr(user, attr, getattr(g.lastuserinfo, attr))
            g.user = user
        else:
            g.user = None

    def login_listener(self):
        self.before_request()
        # Username, fullname and email may have changed, so set them again
        # If the user model does not have these fields, they will not persist beyond one request
        # If we do set these, they won't be saved unless the transaction is committed
        if g.lastuserinfo:
            g.user.username = g.lastuserinfo.username
            g.user.fullname = g.lastuserinfo.fullname
            g.user.email = g.lastuserinfo.email or None
