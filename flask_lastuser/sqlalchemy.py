# -*- coding: utf-8 -*-
"""
    flaskext.lastuser.sqlalchemy
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    SQLAlchemy extensions for Flask-Lastuser.

    :copyright: (c) 2011-12 by HasGeek Media LLP.
    :license: BSD, see LICENSE for more details.
"""

from __future__ import absolute_import

__all__ = ['UserBase', 'UserManager']

import urlparse
from flask import g, current_app, json
from sqlalchemy import Column, Boolean, Integer, String, Unicode, UnicodeText, ForeignKey, Table
from sqlalchemy.orm import deferred, undefer, relationship
from sqlalchemy.ext.declarative import declared_attr
from flask.ext.lastuser import UserInfo, UserManagerBase
from coaster import getbool
from coaster.sqlalchemy import BaseMixin


class UserBase(BaseMixin):
    """
    Base class for user definition.
    """
    __tablename__ = 'user'

    @declared_attr
    def userid(cls):
        return Column(String(22), unique=True, nullable=False)

    @declared_attr
    def username(cls):
        return Column(Unicode(80), unique=True, nullable=True)  # Usernames are optional

    @declared_attr
    def fullname(cls):
        return Column(Unicode(80), default=u'', nullable=False)

    @declared_attr
    def email(cls):
        return Column(Unicode(80), unique=True, nullable=True)  # We may not get an email address

    # Access token info
    @declared_attr
    def lastuser_token(cls):
        return Column(String(22), nullable=True, unique=True)

    @declared_attr
    def lastuser_token_type(cls):
        return Column(Unicode(250), nullable=True)

    @declared_attr
    def lastuser_token_scope(cls):
        return Column(Unicode(250), nullable=True)

    # Userinfo
    @declared_attr
    def _userinfo(cls):
        return deferred(Column('userinfo', UnicodeText, nullable=True))

    @property
    def userinfo(self):
        if not hasattr(self, '_userinfo_cached'):
            if not self._userinfo:
                self._userinfo_cached = {}
            else:
                self._userinfo_cached = json.loads(self._userinfo)
        return self._userinfo_cached

    @userinfo.setter
    def userinfo(self, value):
        if not isinstance(value, dict):
            raise ValueError("userinfo must be a dict")
        self._userinfo_cached = value
        self._userinfo = json.dumps(value)

    def __repr__(self):
        return '<User %s (%s) "%s">' % (self.userid, self.username, self.fullname)

    def organizations_owned(self):
        if self.userinfo.get('organizations') and 'owner' in self.userinfo['organizations']:
            return list(self.userinfo['organizations']['owner'])
        else:
            return []

    def organizations_owned_ids(self):
        return [org['userid'] for org in self.organizations_owned()]

    def user_organizations_owned_ids(self):
        return [self.userid] + self.organizations_owned_ids()

    def organizations_memberof(self):
        if self.userinfo.get('organizations') and 'member' in self.userinfo['organizations']:
            return list(self.userinfo['organizations']['member'])
        else:
            return []

    def organizations_memberof_ids(self):
        return [org['userid'] for org in self.organizations_memberof()]

    def user_organization_memberof_ids(self):
        return [self.userid] + self.organizations_memberof_ids()

    @property
    def profile_url(self):
        return urlparse.urljoin(current_app.config['LASTUSER_SERVER'], 'profile')

    # NOTE: Compatibility definition, please do not use in new code
    user_organization_owned_ids = user_organizations_owned_ids


class TeamBase(BaseMixin):
    __tablename__ = 'team'

    @declared_attr
    def userid(cls):
        return Column(String(22), unique=True, nullable=False)

    @declared_attr
    def orgid(cls):
        return Column(String(22), nullable=False)

    @declared_attr
    def title(cls):
        return Column(Unicode(250), nullable=False)

    @declared_attr
    def owners(cls):
        return Column(Boolean, nullable=False, default=False)

    @declared_attr
    def users(cls):
        return relationship('User', secondary='users_teams', backref='teams')


def make_user_team_table(base):
    return Table('users_teams', base.metadata,
        Column('user_id', Integer, ForeignKey('user.id')),
        Column('team_id', Integer, ForeignKey('team.id'))
        )


class UserManager(UserManagerBase):
    """
    User manager that automatically loads the current user's object from the database.
    """
    def __init__(self, db, usermodel, teammodel=None):
        self.db = db
        self.usermodel = usermodel
        self.teammodel = teammodel
        if teammodel is not None:
            self.users_teams = make_user_team_table(db.Model)

    def load_user(self, userid, create=False):
        # TODO: How do we cache this? Connect to a cache manager
        user = self.usermodel.query.filter_by(userid=userid
            ).options(undefer('_userinfo')).first()
        if user is None:
            if create:
                user = self.usermodel(userid=userid)
                self.db.session.add(user)
        return user

    def make_userinfo(self, user):
        return UserInfo(token=user.lastuser_token,
                        token_type=user.lastuser_token_type,
                        token_scope=user.lastuser_token_scope,
                        userid=user.userid,
                        username=user.username,
                        fullname=user.fullname,
                        email=user.email,
                        permissions=user.userinfo.get('permissions', ()),
                        organizations=user.userinfo.get('organizations'))

    def load_user_userinfo(self, userinfo, update=False):
        """
        Load a user and update data from the userinfo.
        """
        user = self.load_user(userinfo['userid'], create=True)
        # Username, fullname and email may have changed, so set them again
        if user.username != userinfo['username']:
            user.username = userinfo['username']
        if user.fullname != userinfo['fullname']:
            user.fullname = userinfo['fullname']
        if update:
            if user.email != userinfo.get('email'):
                user.email = userinfo.get('email') or None
            user.userinfo = userinfo
        else:
            # Update email only if unset and don't touch userinfo
            if user.email is None:
                user.email = userinfo.get('email') or None

        # Watch for username/email conflicts. Remove from any existing user
        # that have the same username or email, for a conflict can only mean
        # that we didn't hear of this change when it happened in Lastuser
        olduser = self.usermodel.query.filter_by(username=user.username).first()
        if olduser is not None and olduser.id != user.id:
            olduser.username = None
        olduser = self.usermodel.query.filter_by(email=user.email).first()
        if olduser is not None and olduser.id != user.id:
            olduser.email = None

        return user

    def login_listener(self, userinfo, token):
        user = self.load_user_userinfo(userinfo, update=True)
        user.lastuser_token = token['access_token']
        user.lastuser_token_type = token['token_type']
        user.lastuser_token_scope = token['scope']

        g.user = user
        g.lastuserinfo = self.make_userinfo(user)

        # Are we tracking teams? Sync data from Lastuser.

        # TODO: Syncing the list of teams is an org-level operation, not a user-level operation.
        # Move it out of here as there's a higher likelihood of database conflicts
        if self.teammodel:
            org_teams = self.lastuser.org_teams(user.organizations_memberof_ids())
            # TODO: If an org has revoked access to teams for this app, it won't be in org_teams
            # We need to scan for teams in organizations that aren't in this list and revoke them
            user_team_ids = [t['userid'] for t in user.userinfo['teams']]
            # org_teams will be empty if this app's team_access flag isn't set in lastuser
            for orgid, teams in org_teams.items():
                # 1/4: Remove teams that are no longer in lastuser
                removed_teams = self.teammodel.query.filter_by(orgid=orgid).filter(
                    ~self.teammodel.userid.in_([t['userid'] for t in teams])).all()
                for team in removed_teams:
                    self.db.session.delete(team)

                for teamdata in teams:
                    # 2/4: Create teams
                    team = self.teammodel.query.filter_by(userid=teamdata['userid']).first()
                    if team is None:
                        team = self.teammodel(userid=teamdata['userid'],
                                              orgid=teamdata['org'],
                                              title=teamdata['title'],
                                              owners=getbool(teamdata['owners']))
                        self.db.session.add(team)
                    else:
                        # Check if title has changed. The others will never change
                        if team.title != teamdata['title']:
                            team.title = teamdata['title']
                    if team.userid in user_team_ids:
                        # 3/4: Add user to teams they are in
                        if user not in team.users:
                            team.users.append(user)
                    else:
                        # 4/4: Remove users from teams they are no longer in
                        if user in team.users:
                            team.users.pop(user)

        # Commit this so that token info is saved even if the user account is an existing account.
        # This is called before the request is processed by the client app, so there should be no
        # other data in the transaction
        self.db.session.commit()
