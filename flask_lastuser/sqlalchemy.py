"""SQLAlchemy extensions for Flask-Lastuser."""

from collections import defaultdict
from urllib.parse import urljoin

from flask import current_app, g
from pytz import timezone
from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Unicode,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import declarative_mixin, deferred, relationship, synonym, undefer
from werkzeug.utils import cached_property

from coaster.auth import add_auth_attribute, current_auth
from coaster.sqlalchemy import (
    BaseMixin,
    BaseNameMixin,
    JsonDict,
    failsafe_add,
    make_timestamp_columns,
)
from coaster.utils import LabeledEnum, getbool, make_name, require_one_of

from . import UserInfo, UserManagerBase, __, signal_user_looked_up

__all__ = [
    'UserBase',
    'UserBase2',
    'TeamMixin',
    'TeamMembersMixin',
    'TeamBase',
    'TeamBase2',
    'ProfileMixin',
    'ProfileMixin2',
    'ProfileBase',
    'UserManager',
    'IncompleteUserMigrationError',
]


class IncompleteUserMigrationError(Exception):
    """Could not migrate users because of data conflicts."""


class USER_STATUS(LabeledEnum):  # NOQA: N801
    ACTIVE = (0, __('Active'))  # Currently active
    SUSPENDED = (1, __('Suspended'))  # Suspended upstream
    MERGED = (2, __('Merged'))  # Merged locally (all data migrated)
    DELETED = (
        3,
        __('Deleted'),
    )  # Deleted but record preserved for foreign key references


@declarative_mixin
class UserBase(BaseMixin):
    """Base class for user definition."""

    __tablename__ = 'user'

    @declared_attr
    @classmethod
    def userid(cls):
        return Column(String(22), unique=True, nullable=False)

    @declared_attr
    @classmethod
    def username(cls):
        # Nullable since usernames are optional
        return Column(Unicode(80), unique=True, nullable=True)

    @declared_attr
    @classmethod
    def fullname(cls):
        return Column(Unicode(80), default='', nullable=False)

    @declared_attr
    @classmethod
    def email(cls):
        # Nullable since we may not get an email address (out of scope or user hasn't verified one)
        return Column(Unicode(80), unique=True, nullable=True)

    # Access token info
    @declared_attr
    @classmethod
    def lastuser_token(cls):
        # Nullable for legacy reasons. Should not be now.
        return Column(String(22), nullable=True, unique=True)

    @declared_attr
    @classmethod
    def lastuser_token_type(cls):
        # Nullable for legacy reasons. Should not be now.
        return Column(Unicode(250), nullable=True)

    @declared_attr
    @classmethod
    def lastuser_token_scope(cls):
        # Nullable for legacy reasons. Should not be now.
        return Column(Unicode(250), nullable=True)

    @property
    def access_scope(self):
        # The "or u''" below is required since the field is nullable
        return (self.lastuser_token_scope or '').split(' ')

    # Userinfo
    @declared_attr
    @classmethod
    def userinfo(cls):
        # Userinfo is transient until we get app-level caching into Flask-Lastuser
        return deferred(Column('userinfo', JsonDict, nullable=True))

    @classmethod
    def get(cls, username=None, userid=None, defercols=True):
        """Return a User with the given username or userid.

        :param str username: Username to lookup
        :param str userid: Userid to lookup
        """
        param, value = require_one_of(True, username=username, userid=userid)
        query = cls.query.filter_by(**{param: value})
        if not defercols:
            query = query.options(undefer(cls.userinfo))
        return query.one_or_none()

    @property
    def timezone(self):
        """The user's timezone as a string."""
        # Stored in userinfo since it was introduced later and a new column
        # will require migrations in downstream apps.
        return (
            self.userinfo
            and self.userinfo.get('timezone')
            or current_app.config.get('TIMEZONE')
        )

    @property
    def oldids(self):
        """List of the user's old userids (after merging accounts in Lastuser)."""
        # Stored in userinfo since it was introduced later and a new column
        # will require migrations in downstream apps. Also, this is an array
        # and will require (a) a joined table, (b) Postgres-specific arrays, or (c) data massaging
        # by joining with spaces, like "access_scope" above.
        return self.userinfo and self.userinfo.get('oldids') or []

    # Use cached_property here because pytz.timezone is relatively slow:
    #
    # python -m timeit -s 'from pytz import timezone' 'timezone("Asia/Kolkata")'
    # 100000 loops, best of 3: 4.07 usec per loop
    # python -m timeit -s 'from pytz import timezone; tz = {"Asia/Kolkata": timezone("Asia/Kolkata")}; gtz=lambda t: tz[t]'\
    # 'gtz("Asia/Kolkata")'
    # 1000000 loops, best of 3: 0.229 usec per loop
    @cached_property
    def tz(self):
        """The user's timezone as a timezone object."""
        if self.timezone:
            return timezone(self.timezone)
        return None

    @property
    def phone(self):
        """The user's phone number, if verified and present in the scope."""
        # Stored in userinfo since it was introduced later and a new column
        # will require migrations in downstream apps.
        return self.userinfo and self.userinfo.get('phone')

    @property
    def avatar(self):
        return self.userinfo and self.userinfo.get('avatar')

    def __repr__(self):
        return f'<User {self.userid} ({self.username}) "{self.fullname}">'

    def merge_accounts(self):
        """Do nothing. Implemented from UserBase2 onwards."""

    def organizations_owned(self):
        """Organizations owned by this user."""
        if (
            self.userinfo
            and self.userinfo.get('organizations')
            and 'owner' in self.userinfo['organizations']
        ):
            return list(self.userinfo['organizations']['owner'])
        return []

    def organizations_owned_ids(self):
        """Userids of the organizations owned by this user."""
        return [org['userid'] for org in self.organizations_owned()]

    def user_organizations_owned_ids(self):
        """Userids of the user and all the organizations owned by this user."""
        return [self.userid, *self.organizations_owned_ids()]

    def organizations_adminof(self):
        """Organizations that this user is an admin of."""
        if (
            self.userinfo
            and self.userinfo.get('organizations')
            and 'admin' in self.userinfo['organizations']
        ):
            return list(self.userinfo['organizations']['admin'])
        return []

    def organizations_adminof_ids(self):
        """Userids of the organizations this user is an admin of."""
        return [org['userid'] for org in self.organizations_adminof()]

    def user_organizations_adminof_ids(self):
        """Userids of the user and all the organizations the user is an admin of."""
        return [self.userid, *self.organizations_adminof_ids()]

    def owner_of(self, userid):
        if not isinstance(userid, str):
            userid = userid.userid
        return userid in self.user_organizations_owned_ids()

    def admin_of(self, userid):
        if not isinstance(userid, str):
            userid = userid.userid
        return userid in self.user_organizations_adminof_ids()

    def team_info(self):
        return self.userinfo.get('teams')

    def team_ids(self):
        return [team['userid'] for team in self.userinfo.get('teams', [])]

    def user_team_ids(self):
        return [self.userid] + [
            team['userid'] for team in self.userinfo.get('teams', [])
        ]

    def teammember_of(self, userid):
        if not isinstance(userid, str):
            userid = userid.userid
        return userid in self.team_ids()

    def allowner_ids(self):
        return [self.userid, *self.organizations_owned_ids(), *self.team_ids()]

    @property
    def profile_url(self):
        """URL to the user's profile. Can be overridden by subclasses."""
        return urljoin(current_app.config['LASTUSER_SERVER'], 'account')

    @property
    def profile_name(self):
        """'name' value for the profile linked to this user."""
        return self.username or self.userid

    @property
    def pickername(self):
        """Label name for this user, for identifying them in dropdown lists."""
        if self.username:
            return f"{self.fullname} (@{self.username})"
        return self.fullname

    def organization_links(self):
        """Links to the user's organizations on the current site."""
        return []

    def owner_choices(self):
        """Return userids and titles of users and owned organizations for selection lists."""
        return [(self.userid, self.pickername)] + [
            (o['userid'], '{title} (@{name})'.format(title=o['title'], name=o['name']))
            for o in self.organizations_owned()
        ]

    def teamowner_choices(self):
        """Return userids and titles of user and all teams the user is a member of, grouped by organization."""
        orgs = {
            org['userid']: org
            for byorgtype in self.userinfo.get('organizations', {}).values()
            for org in byorgtype
        }
        teamsbyorg = defaultdict(list)
        for team in self.userinfo.get('teams', []):
            teamsbyorg[team['org']].append(team)
        return [(self.userid, self.pickername)] + [
            (
                '{title} (@{name})'.format(
                    title=orgs.get(orgid, {}).get('title', ''),
                    name=orgs.get(orgid, {}).get('name', ''),
                ),
                [
                    (
                        team['userid'],
                        '{} / {}'.format(
                            orgs.get(orgid, {}).get('title', ''), team['title']
                        ),
                    )
                    for team in sorted(teams, key=lambda t: t['title'])
                ],
            )
            for orgid, teams in sorted(
                teamsbyorg.items(), key=lambda row: orgs.get(row[0], {}).get('title')
            )
        ]

    def allowner_choices(self):
        """Return userids and titles of the user, all organizations owned by the user, and all teams the user
        is a member of.
        """
        orgs = {
            org['userid']: org
            for byorgtype in self.userinfo.get('organizations', {}).values()
            for org in byorgtype
        }
        teamsbyorg = defaultdict(list)
        for team in self.userinfo.get('teams', []):
            teamsbyorg[team['org']].append(team)
        for orgid in orgs:
            if orgid not in teamsbyorg:
                teamsbyorg[orgid] = []
        orgids = sorted(
            teamsbyorg.keys(), key=lambda orgid: orgs.get(orgid, {}).get('title')
        )
        ownedids = set(self.organizations_owned_ids())

        result = [(self.userid, self.pickername)]
        for orgid in orgids:
            if orgid in ownedids:
                result.append(
                    (
                        orgid,
                        '{title} (@{name})'.format(
                            title=orgs[orgid]['title'], name=orgs[orgid]['name']
                        ),
                    )
                )
            for team in sorted(teamsbyorg[orgid], key=lambda team: team['title']):
                result.append(
                    (
                        team['userid'],
                        '{} / {}'.format(
                            orgs.get(orgid, {}).get('title', ''), team['title']
                        ),
                    )
                )

        return result

    # Compatibility names. Do not use in new code.
    organizations_memberof = organizations_adminof
    organizations_memberof_ids = organizations_adminof_ids
    user_organizations_memberof_ids = user_organizations_adminof_ids
    user_organization_memberof_ids = user_organizations_adminof_ids
    member_of = admin_of


def _do_merge_into(instance, other, helper_method=None):
    assert instance != other  # noqa S101

    # User id column (for foreign keys)
    id_column = instance.__class__.__table__.c.id  # 'id' is from IdMixin via BaseMixin
    # Session (for queries)
    session = instance.query.session

    # Keep track of all migrated tables
    migrated_tables = set()
    safe_to_remove_instance = True

    # Find the Base class
    base = instance.__class__
    while True:
        goparent = False
        for cbase in base.__bases__:
            if hasattr(cbase, 'metadata') and isinstance(cbase.metadata, MetaData):
                base = cbase
                goparent = True
                break
        if not goparent:
            break

    def do_migrate_table(table):
        target_columns = []
        for column in table.columns:
            for fkey in column.foreign_keys:
                if fkey.column is id_column:
                    # This table needs migration on this column
                    target_columns.append(column)
                    break

        # Check for unique constraint on instance id columns (single or multi-index)
        # If so, return False (migration incomplete)
        for column in target_columns:
            if column.unique:
                # XXX: This will fail for secondary relationship tables, which
                # will have a unique index but no model on which to place
                # helper_method, unless one of the related models handles
                # migrations AND signals a way for this table to be skipped
                # here. This is why model.helper_method below (migrate_user or
                # migrate_profile) returns a list of table names it has
                # processed.
                current_app.logger.debug(
                    "do_migrate_table interrupted because column is unique: {column}",
                    extra={'column': column},
                )
                return False

        # Now check for multi-column indexes
        for constraint in table.constraints:
            if isinstance(constraint, (PrimaryKeyConstraint, UniqueConstraint)):
                for column in constraint.columns:
                    if column in target_columns:
                        # The target column (typically user_id) is part of a unique
                        # or primary key constraint. We can't migrate automatically.
                        current_app.logger.debug(
                            "do_migrate_table interrupted because column is part of a "
                            "unique constraint: {column}",
                            extra={'column': column},
                        )
                        return False

        # TODO: If this table uses Flask-SQLAlchemy's bind_key mechanism, session.execute won't bind
        # to the correct engine, so the table cannot be migrated. If we attempt to retrieve and connect
        # to the correct engine, we may lose the transaction. We need to confirm this.
        if table.info.get('bind_key'):
            current_app.logger.debug(
                "do_migrate_table interrupted because table has bind_key: {table}",
                extra={'table': table.name},
            )
            return False

        for column in target_columns:
            session.execute(
                table.update()
                .where(column == instance.id)
                .values(**{column.name: other.id})
            )
            session.flush()

        # All done, table successfully migrated. Hurrah!
        return True

    # Look up all subclasses of this base class
    for model in base.__subclasses__():
        if model != instance.__class__:
            if helper_method and hasattr(model, helper_method):
                try:
                    result = getattr(model, helper_method)(instance, other)
                    session.flush()
                    if isinstance(result, (list, tuple, set)):
                        migrated_tables.update(result)
                    migrated_tables.add(model.__table__.name)
                except IncompleteUserMigrationError:
                    safe_to_remove_instance = False
                    current_app.logger.debug(
                        "_do_merge_into interrupted because"
                        " IncompleteUserMigrationError raised by {model}",
                        extra={'model': model},
                    )
            else:
                # No model-backed migration. Figure out all foreign key references to user table
                if not do_migrate_table(model.__table__):
                    safe_to_remove_instance = False
                migrated_tables.add(model.__table__.name)

    # Now look in the metadata for any tables we missed
    for table in base.metadata.tables.values():
        if table.name not in migrated_tables:
            if not do_migrate_table(table):
                safe_to_remove_instance = False
            migrated_tables.add(table.name)

    return safe_to_remove_instance


@declarative_mixin
class StatusMixin:
    """Mixin class providing the status column and helper methods."""

    @declared_attr
    @classmethod
    def status(cls):
        return Column(Integer, nullable=False, default=USER_STATUS.ACTIVE)

    @property
    def is_active(self):
        """Is the user active? This is local status, not upstream status from Lastuser."""
        return self.status == USER_STATUS.ACTIVE

    @property
    def is_suspended(self):
        """Is the user suspended? This is local status, not upstream status from Lastuser."""
        return self.status == USER_STATUS.SUSPENDED

    @property
    def is_merged(self):
        """Is the user merged? This is local status, not upstream status from Lastuser."""
        return self.status == USER_STATUS.MERGED


@declarative_mixin
class UserMergeMixin(StatusMixin):
    """Mixin class adding support for user status and merging. Don't use this mixin
    directly. Use :class:`UserBase2` or a later base class instead.
    """

    @classmethod
    def get(cls, username=None, userid=None, defercols=True):
        """Return a User with the given username or userid. Only active users are
        returned. For merged users, the linked active user is returned.

        :param str username: Username to lookup
        :param str userid: Userid to lookup
        """
        user = super().get(username=username, userid=userid, defercols=defercols)

        if user and user.status == USER_STATUS.MERGED:
            user = user.merged_user()
        if user and user.is_active:
            return user
        return None

    def merged_user(self):
        """If this account has been merged into another, return that account, else
        return this. This method queries the upstream Lastuser server since
        data on merged users is not stored locally in a queryable format (ie,
        ``user.userinfo['oldids']`` of the other account).
        """
        if self.status != USER_STATUS.MERGED:
            return self
        lastuser = current_app.extensions.get('lastuser')
        if lastuser:
            userdata = lastuser.getuser_by_userid(self.userid)
            if userdata:
                return self.get(userid=userdata['userid'])
            return None
        return None

    def merge_accounts(self):
        if self.oldids:
            for olduser in self.__class__.query.filter(
                self.__class__.userid.in_(self.oldids)
            ).all():
                olduser.merge_into(self)

    def merge_into(self, user):
        """Merge self into the specified user and relink all."""
        current_app.logger.debug(
            "Preparing to merge {self} into {user}.",
            extra={'self': repr(self), 'user': repr(user)},
        )
        if self.status == USER_STATUS.MERGED:
            current_app.logger.debug(
                "Ignoring merge request because we are already merged."
            )
            return None  # We are already merged, so ignore this call

        safe_to_remove_user = _do_merge_into(self, user, 'migrate_user')

        # Release claim to username and email (unique properties)
        # and mark self as merged
        self.username = None
        self.email = None
        if safe_to_remove_user:
            self.status = USER_STATUS.MERGED
            current_app.logger.debug("{self} is now merged", extra={'self': repr(self)})

        current_app.logger.debug(
            "Safe to remove {self}: {user}",
            extra={'self': repr(self), 'user': repr(safe_to_remove_user)},
        )
        return safe_to_remove_user


@declarative_mixin
class UserBase2(UserMergeMixin, UserBase):
    """Version 2 of UserBase, adding support for user status and merging. Inherits from
    :class:`UserMergeMixin` and :class:`UserBase`.
    """


@declarative_mixin
class TeamMixin(BaseMixin):
    @declared_attr
    @classmethod
    def userid(cls):
        return Column(String(22), unique=True, nullable=False)

    @declared_attr
    @classmethod
    def orgid(cls):
        return Column(String(22), index=True, nullable=False)

    @declared_attr
    @classmethod
    def title(cls):
        return Column(Unicode(250), nullable=False)

    @declared_attr
    @classmethod
    def owners(cls):
        return Column(Boolean, nullable=False, default=False)

    @declared_attr
    @classmethod
    def users(cls):
        return relationship('User', secondary='users_teams', backref='teams')

    @classmethod
    def migrate_user(cls, olduser, newuser):
        """Substitute the old user's team membership with the new user and return the list of
        tables affected.
        """
        session = cls.query.session
        users_teams = cls.metadata.tables['users_teams']

        affected_team_ids = {
            r.team_id
            for r in session.query(users_teams).filter_by(user_id=olduser.id).all()
        }

        # newuser is already in these teams
        unaffected_team_ids = {
            r.team_id
            for r in session.query(users_teams).filter_by(user_id=newuser.id).all()
        }

        migrate_team_ids = affected_team_ids - unaffected_team_ids
        remove_team_ids = affected_team_ids.intersection(unaffected_team_ids)

        session.execute(
            users_teams.update()
            .where(users_teams.c.user_id == olduser.id)
            .where(users_teams.c.team_id.in_(migrate_team_ids))
            .values(user_id=newuser.id)
        )
        session.execute(
            users_teams.delete().where(
                users_teams.c.user_id == olduser.id,
                users_teams.c.team_id.in_(remove_team_ids),
            )
        )

        # We handled migrations in the users_teams table, so let the caller know
        return ['users_teams']

    @classmethod
    def get(cls, userid):
        """Get a Team by its userid."""
        return cls.query.filter_by(userid=userid).one_or_none()

    def update_from_lastuser(self):
        """Update information about this team from Lastuser."""
        # TODO


@declarative_mixin
class TeamBase(TeamMixin):
    __tablename__ = 'team'


@declarative_mixin
class TeamMembersMixin:
    @declared_attr
    @classmethod
    def members(cls):
        return Column(Boolean, nullable=False, default=False)


@declarative_mixin
class TeamBase2(TeamMixin, TeamMembersMixin):
    __tablename__ = 'team'


@declarative_mixin
class ProfileMixin:
    """ProfileMixin provides methods to assist with creating Profile models (which represent
    both User and Organization models), and keeping them updated as user data changes.

    ProfileMixin does not provide any columns (apart from aliasing userid to buid).
    Subclasses must provide their own columns including the mandatory name,
    title and buid or userid. Use ProfileBase to get these columns.
    """

    @declared_attr
    @classmethod
    def userid(cls):
        """Synonym for buid if the model has no existing userid column."""
        return synonym('buid')

    def owner_is(self, user):
        if not user:
            return False
        return (
            self.userid == user.userid or self.userid in user.organizations_owned_ids()
        )

    def admin_is(self, user):
        if not user:
            return False
        return (
            self.userid == user.userid
            or self.userid in user.organizations_adminof_ids()
        )

    @property
    def pickername(self):
        if self.userid == self.name:
            return self.title
        return f'{self.title} (@{self.name})'

    def permissions(self, actor, inherited=None):
        parent = super()
        if hasattr(parent, 'permissions'):
            perms = parent.permissions(actor, inherited)
        else:
            perms = set()
        perms.add('view')
        if actor and (
            self.userid in actor.user_organizations_adminof_ids()
            or self.userid in actor.oldids
        ):
            perms.add('edit')
            perms.add('delete')
            perms.add('new')
        return perms

    @classmethod
    def update_from_user(
        cls,
        user,
        session,
        parent=None,
        type_user=None,
        type_org=None,
        type_col='type',
        make_user_profiles=True,
        make_org_profiles=True,
    ):
        """Update profiles from the given user and user's organizations.

        :param user: User account with organization data.
        :param session: Database session (typically db.session).
        :param parent: Parent object, if applicable.
        :param type_user: Type value for user profiles, if applicable.
        :param type_org: Type value for organization profiles, if applicable.
        :param unicode type_col: Column for type value, if applicable.
        :param bool make_user_profiles: Should user profiles be created?
        :param bool make_org_profiles: Should organization profiles be created?
        """
        idsnames = {user.userid: {'name': user.profile_name, 'title': user.fullname}}
        for org in user.organizations_adminof():
            idsnames[org['userid']] = {'name': org['name'], 'title': org['title']}
        namesids = {value['name']: key for key, value in idsnames.items()}

        # First, check if Profile userids and names match
        for profile in cls.query.filter(cls.name.in_(list(namesids.keys()))).all():
            if profile.userid != namesids[profile.name]:
                # This profile's userid and name don't match. Knock off the name
                profile.name = make_name(
                    profile.userid,
                    maxlength=250,
                    checkused=lambda c: (
                        bool(session.query(cls.name).filter_by(name=c).first())
                    ),
                )

        # Flush this to the db for constraint integrity
        session.flush()

        # Second, check the other way around and keep this list of profiles
        profiles = {
            p.userid: p
            for p in cls.query.filter(cls.userid.in_(list(idsnames.keys()))).all()
        }
        for profile in profiles.values():
            if profile.name != idsnames[profile.userid]['name']:
                profile.name = idsnames[profile.userid]['name']
            if profile.title != idsnames[profile.userid]['title']:
                profile.title = idsnames[profile.userid]['title']

        # Flush this too
        session.flush()

        # Third, make new profiles if required
        if make_user_profiles and user.userid not in profiles:
            if parent is not None:
                profile = cls(
                    userid=user.userid,
                    name=user.profile_name,
                    title=user.fullname,
                    parent=parent,
                )
            else:
                profile = cls(
                    userid=user.userid, name=user.profile_name, title=user.fullname
                )
            if type_user is not None:
                setattr(profile, type_col, type_user)
            session.add(profile)

        if make_org_profiles:
            for org in user.organizations_adminof():
                if org['userid'] not in profiles:
                    if parent is not None:
                        profile = cls(
                            userid=org['userid'],
                            name=org['name'],
                            title=org['title'],
                            parent=parent,
                        )
                    else:
                        profile = cls(
                            userid=org['userid'], name=org['name'], title=org['title']
                        )
                    if type_org is not None:
                        setattr(profile, type_col, type_org)
                    session.add(profile)

        # Fourth, migrate profiles if there are any matching the user's old ids
        if user.oldids:
            profile = cls.query.filter_by(userid=user.userid).first()
            if profile:
                oldprofiles = cls.query.filter(cls.userid.in_(user.oldids)).all()
                for op in oldprofiles:
                    op.merge_into(profile)

    def merge_into(self, profile):
        """Move all data from self to the other profile, typically when merging user
        accounts. Note that ProfileMixin2.merge_into replaces this method.
        """
        assert isinstance(profile, ProfileMixin)  # noqa S101
        assert profile != self  # noqa S101

        safe_to_remove_profile = _do_merge_into(self, profile, 'migrate_profile')

        # Release claim to name (unique property) and delete self if safe
        self.name = self.userid
        if safe_to_remove_profile:
            self.query.session.delete(self)
        return safe_to_remove_profile


@declarative_mixin
class ProfileMixin2(StatusMixin, ProfileMixin):
    @classmethod
    def get(cls, name=None, userid=None, buid=None):
        require_one_of(name=name, userid=userid, buid=buid)

        if userid:
            profile = cls.query.filter_by(
                userid=userid, status=USER_STATUS.ACTIVE
            ).one_or_none()
        elif buid:
            # buid is used in Nodular, where it has slightly different semantics from
            # userid: buid always gets the Node if it exists, so there's no check
            # against the status column
            profile = cls.query.filter_by(buid=buid).one_or_none()
        else:
            profile = cls.query.filter_by(
                name=name, status=USER_STATUS.ACTIVE
            ).one_or_none()

        if profile.is_merged:
            profile = profile.merged_profile()
        if profile.is_active:
            return profile
        return None

    def merged_profile(self):
        """If this profile has been merged into another, return that profile, else
        return this. This method queries the upstream Lastuser server since
        data on merged profiles is not stored locally in a queryable format (ie,
        ``user.userinfo['oldids']`` of the other profile's user).
        """
        if self.status != USER_STATUS.MERGED:
            return self
        lastuser = current_app.extensions.get('lastuser')
        if lastuser:
            userdata = lastuser.getuser_by_userid(self.userid)
            if userdata:
                return self.get(userid=userdata['userid'])
            return None
        return None

    def update_from_lastuser(self):
        """Query Lastuser for current details of this userid and update as necessary."""
        lastuser = current_app.extensions.get('lastuser') if current_app else None
        if lastuser:
            userinfo = lastuser.getuser_by_userid(self.userid)
            if userinfo:
                if userinfo['userid'] != self.userid and self.userid in userinfo.get(
                    'oldids', []
                ):
                    # This Profile has gone away. Does the new profile exist here?
                    with self.query.session.no_autoflush:
                        profile = self.query.filter_by(
                            userid=userinfo['userid']
                        ).first()
                    if profile is not None:
                        safe_to_remove = self.merge_into(profile)
                        if safe_to_remove:
                            self.query.session.delete(self)
                    else:
                        # The new profile isn't here yet, so assume their identity
                        self.userid = userinfo['userid']
                        self.status = USER_STATUS.ACTIVE
                if userinfo['name'] is not None:
                    with self.query.session.no_autoflush:
                        moveprofile = self.query.filter_by(
                            name=userinfo['name']
                        ).first()
                    if moveprofile and moveprofile != self:
                        # There's another profile holding our desired name. Move it out of the way
                        moveprofile.name = moveprofile.userid
                        self.query.session.flush()
                self.name = userinfo['name'] or userinfo['userid']
                self.title = userinfo['title']
            else:
                # Lastuser was unreachable or doesn't know about us anymore (FIXME: find out which)
                self.name = self.userid
                self.status = USER_STATUS.DELETED

    def merge_into(self, profile):
        """Move all data from self to the other profile, typically when merging user accounts."""
        if self.status == USER_STATUS.MERGED:
            return True

        assert isinstance(profile, ProfileMixin2)  # noqa: S101
        assert profile != self  # noqa: S101

        safe_to_remove_profile = _do_merge_into(self, profile, 'migrate_profile')

        # Release claim to name (unique property) and mark self as merged
        self.name = self.userid
        if safe_to_remove_profile:
            self.status = USER_STATUS.MERGED
        return safe_to_remove_profile

    @classmethod
    def update_all_from_lastuser(cls):
        """Update all profiles from Lastuser."""
        for profile in cls.query:
            profile.update_from_lastuser()
            cls.query.session.flush()


@declarative_mixin
class ProfileBase(ProfileMixin2, BaseNameMixin):
    """Base class for profiles."""

    @declared_attr
    @classmethod
    def userid(cls):
        return Column(Unicode(22), nullable=False, unique=True)

    @declared_attr
    @classmethod
    def buid(cls):
        """Synonym for userid."""
        return synonym('userid')

    def __repr__(self):
        return f'<{self.__class__.__name__} {self.name} "{self.title}">'


def make_user_team_table(base, timezone=False):
    if 'users_teams' in base.metadata.tables:
        return base.metadata.tables['users_teams']
    return Table(
        'users_teams',
        base.metadata,
        *make_timestamp_columns(timezone=timezone),
        Column('user_id', Integer, ForeignKey('user.id'), primary_key=True),
        Column('team_id', Integer, ForeignKey('team.id'), primary_key=True),
    )


class UserManager(UserManagerBase):
    """User manager that automatically loads the current user's object from the database."""

    def __init__(self, db, usermodel, teammodel=None):
        self.db = db
        self.usermodel = usermodel
        self.teammodel = teammodel
        if teammodel is not None:
            self.users_teams = make_user_team_table(
                db.Model, timezone=getattr(usermodel, '__with_timezone__', False)
            )

    def load_user(self, userid, uuid=None, create=False):
        # TODO: How do we cache this? Connect to a cache manager
        if (
            uuid
            and hasattr(self.usermodel, '__uuid_primary_key__')
            and self.usermodel.__uuid_primary_key__
        ):
            user = self.usermodel.query.get(
                uuid
            )  # This loads from SQLAlchemy session cache
        elif hasattr(self.usermodel, 'get'):
            user = self.usermodel.get(userid=userid, defercols=False)
        else:
            user = (
                self.usermodel.query.filter_by(userid=userid)
                .options(undefer(self.__class__.userinfo))
                .one_or_none()
            )
        if user is None and create:
            user = self.usermodel(userid=userid)
            if (
                uuid
                and hasattr(self.usermodel, '__uuid_primary_key__')
                and self.usermodel.__uuid_primary_key__
            ):
                user.id = uuid
            failsafe_add(self.db.session, user, userid=userid)
        return user

    def load_user_by_username(self, username):
        if hasattr(self.usermodel, 'get'):
            return self.usermodel.get(username=username)
        return self.usermodel.query.filter_by(username=username).first()

    def make_userinfo(self, user):
        return UserInfo(
            token=user.lastuser_token,
            token_type=user.lastuser_token_type,
            token_scope=user.lastuser_token_scope,
            userid=user.userid,
            username=user.username,
            fullname=user.fullname,
            email=user.email,
            permissions=user.userinfo.get('permissions', ()) if user.userinfo else (),
            organizations=user.userinfo.get('organizations') if user.userinfo else None,
        )

    def load_user_userinfo(self, userinfo, access_token=None, update=False):
        """Load a user and update data from the userinfo."""
        user = self.load_user(
            userid=userinfo['userid'], uuid=userinfo.get('uuid'), create=True
        )

        # Watch for username/email conflicts. Remove from any existing user
        # that have the same username or email, for a conflict can only mean
        # that we didn't hear of this change when it happened in Lastuser
        olduser = self.usermodel.query.filter_by(username=userinfo['username']).first()
        if olduser is not None and olduser.id != user.id:
            olduser.username = None
        if userinfo.get('email'):
            olduser = self.usermodel.query.filter_by(
                email=userinfo.get('email')
            ).first()
            if olduser is not None and olduser.id != user.id:
                olduser.email = None

        # Next, watch for lastuser_token conflicts. This can happen when user
        # accounts are merged and we haven't yet detected that.
        if access_token is not None:
            olduser = self.usermodel.query.filter_by(
                lastuser_token=access_token
            ).first()
            if olduser is not None and olduser.id != user.id:
                olduser.lastuser_token = None
                olduser.lastuser_token_type = None
                olduser.lastuser_token_scope = None

        # Flush the changes before updating the current user account
        self.db.session.flush()

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

        return user

    def login_listener(self, userinfo, token):
        user = self.load_user_userinfo(userinfo, token['access_token'], update=True)
        user.lastuser_token = token['access_token']
        user.lastuser_token_type = token['token_type']
        user.lastuser_token_scope = token['scope']

        add_auth_attribute('user', user)
        g.user = user  # XXX: Deprecated, for backward compatibility only
        add_auth_attribute('lastuserinfo', self.make_userinfo(user))

        self.update_teams(user)
        signal_user_looked_up.send(current_auth.user)
        return user

    def update_teams(self, user):
        # Are we tracking teams? Sync data from Lastuser.
        if self.teammodel:
            allteamdata = user.userinfo.get('teams', [])
            user_team_ids = [t['userid'] for t in allteamdata if t.get('member')]

            org_teams = {}
            for t in allteamdata:
                org_teams.setdefault(t['org'], []).append(t)

            for orgid, teams in org_teams.items():
                if {'*', 'teams', 'teams/*'}.intersection(
                    user.access_scope
                ) and orgid in user.organizations_owned_ids():
                    # 1/4: Remove teams that are no longer in lastuser, provided we have
                    # an authoritative list ('teams' is in scope and the user owns the
                    # organization)
                    removed_teams = (
                        self.teammodel.query.filter_by(orgid=orgid)
                        .filter(
                            ~self.teammodel.userid.in_([t['userid'] for t in teams])
                        )
                        .all()
                    )
                    for team in removed_teams:
                        self.db.session.delete(team)

                for teamdata in teams:
                    # 2/4: Create teams
                    team = self.teammodel.query.filter_by(
                        userid=teamdata['userid']
                    ).first()
                    if team is None:
                        team = self.teammodel(
                            userid=teamdata['userid'],
                            orgid=teamdata['org'],
                            title=teamdata['title'],
                            owners=getbool(teamdata['owners']),
                        )
                        team.members = False  # Lastuser no longer supports Members team
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
                            team.users.remove(user)

        # Commit this so that token info is saved even if the user account is an
        # existing account. This is called before the request is processed by the client
        # app, so there should be no other data in the transaction
        self.db.session.commit()
        # Commit this so that token info is saved even if the user account is an
        # existing account. This is called before the request is processed by the client
        # app, so there should be no other data in the transaction
        self.db.session.commit()
