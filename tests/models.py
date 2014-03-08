# -*- coding: utf-8 -*-

from coaster.db import db
from flask.ext.lastuser.sqlalchemy import UserBase2, TeamBase, ProfileBase


class User(UserBase2, db.Model):
    __tablename__ = 'user'


class Team(TeamBase, db.Model):
    __tablename__ = 'team'


class Profile(ProfileBase, db.Model):
    __tablename__ = 'profile'
