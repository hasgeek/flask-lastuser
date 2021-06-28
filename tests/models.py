# -*- coding: utf-8 -*-
from coaster.db import db
from flask_lastuser.sqlalchemy import ProfileBase, TeamBase, UserBase2


class User(UserBase2, db.Model):
    __tablename__ = 'user'


class Team(TeamBase, db.Model):
    __tablename__ = 'team'


class Profile(ProfileBase, db.Model):
    __tablename__ = 'profile'
