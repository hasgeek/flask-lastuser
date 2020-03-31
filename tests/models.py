# -*- coding: utf-8 -*-

from flask_lastuser.sqlalchemy import ProfileBase, TeamBase, UserBase2

from coaster.db import db


class User(UserBase2, db.Model):
    __tablename__ = 'user'


class Team(TeamBase, db.Model):
    __tablename__ = 'team'


class Profile(ProfileBase, db.Model):
    __tablename__ = 'profile'
