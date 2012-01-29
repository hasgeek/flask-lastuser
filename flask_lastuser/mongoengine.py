# -*- coding: utf-8 -*-
"""
    flaskext.lastuser.mongoengine
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    mongoengine extensions for flask-lastuser.

    :copyright: (c) 2012 by HasGeek Media LLP.
    :license: BSD, see LICENSE for more details.
"""
from __future__ import absolute_import

__all__ = ['User', 'UserManager']

from flask import g
from mongoengine import Document, DateTimeField, StringField, signals
from datetime import datetime


class User(Document):
    """
    Base class for user definition.
    """
    userid = StringField(max_length=22, unique=True, required=True)
    # Usernames are optional
    username = StringField(max_length=80, unique=True, required=False)
    fullname = StringField(max_length=80, default=u'', required=True)
    # We may not get an email address
    email = StringField(max_length=80, unique=True, required=False)
    # Access token info
    lastuser_token = StringField(max_length=22, unique=True)
    lastuser_token_type = StringField(max_length=250)
    lastuser_token_scope = StringField(max_length=250)

    created_at = DateTimeField(default=datetime.now, required=True)
    updated_at = DateTimeField(required=True)

    def __repr__(self):
        return ('<User %s (%s) "%s">' %
            (self.userid, self.username, self.fullname))
    
    @classmethod
    def pre_save(cls, sender, document, **kwargs):
        document.updated_at = datetime.now()

signals.pre_save.connect(User.pre_save, sender=User)


class UserManager(object):
    """
    User manager that automatically loads the current user's
    object from the database.
    """

    def __init__(self, userobject, usermodel):
        self.user = userobject
        self.usermodel = usermodel

    def before_request(self):
        # TODO: How do we cache this? Connect to a cache manager
        if g.lastuserinfo:
            self.user = (self.usermodel.objects(userid=g.lastuserinfo.userid).
                        first())
            if self.user is None:
                self.user = self.usermodel(userid=g.lastuserinfo.userid)
                self.user.username = g.lastuserinfo.username
                self.user.fullname = g.lastuserinfo.fullname
                self.user.email = g.lastuserinfo.email or None
            else:
                for attr in ['username', 'fullname', 'email']:
                    if not hasattr(self.user, attr):
                        setattr(self.user, attr, getattr(g.lastuserinfo, attr))
            g.user = self.user
        else:
            g.user = None

    def login_listener(self):
        self.before_request()
        # Username, fullname and email may have changed, so set them again
        # If the user model does not have these fields,
        # they will not persist beyond one request
        if g.lastuser_token:
            g.user.lastuser_token = g.lastuser_token['access_token']
            g.user.lastuser_token_type = g.lastuser_token['token_type']
            g.user.lastuser_token_scope = g.lastuser_token['scope']

        if g.lastuserinfo:
            g.user.username = g.lastuserinfo.username
            g.user.fullname = g.lastuserinfo.fullname
            g.user.email = g.lastuserinfo.email or None
        g.user.save()
