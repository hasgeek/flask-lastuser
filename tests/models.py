"""Test model creation."""

from flask_sqlalchemy import SQLAlchemy

from flask_lastuser.sqlalchemy import ProfileBase, TeamBase, UserBase2

db = SQLAlchemy()


class User(UserBase2, db.Model):  # type: ignore[name-defined]
    __tablename__ = 'user'


class Team(TeamBase, db.Model):  # type: ignore[name-defined]
    __tablename__ = 'team'


class Profile(ProfileBase, db.Model):  # type: ignore[name-defined]
    __tablename__ = 'profile'
