# -*- coding: utf-8 -*-
"""
flask_lastuser
~~~~~~~~~~~~~~

Lastuser extension for Flask
"""


from functools import wraps
import uuid
from datetime import timedelta
from six.moves.urllib.parse import urlsplit, urljoin
import requests
import urllib.request, urllib.parse, urllib.error
import re
import weakref
import itsdangerous
from flask_babelex import Domain
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict
from coaster.utils import getbool, is_collection, utcnow
from coaster.auth import add_auth_attribute, current_auth, request_has_auth
from coaster.views import get_current_url, get_next_url

from flask import session, g, redirect, url_for, request, flash, abort, Response, jsonify, json, current_app
from flask.signals import Namespace

from . import translations
from ._version import *  # NOQA

# Signals
lastuser_signals = Namespace()

signal_user_session_refreshed = lastuser_signals.signal('user-session-refreshed')
signal_user_session_expired = lastuser_signals.signal('user-session-expired')
signal_user_looked_up = lastuser_signals.signal('user-looked-up')
signal_before_wrapped_view = lastuser_signals.signal('before-wrapped-view')

# Translations
flask_lastuser_translations = Domain(translations.__path__[0], domain='flask_lastuser')
_ = flask_lastuser_translations.gettext
__ = flask_lastuser_translations.lazy_gettext

# Bearer token, as per http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-15#section-2.1
auth_bearer_re = re.compile("^Bearer ([a-zA-Z0-9_.~+/-]+=*)$")


class LastuserConfigException(Exception):
    pass


class LastuserException(Exception):
    pass


class LastuserApiException(LastuserException):
    pass


class LastuserResourceException(LastuserException):
    pass


class LastuserResourceConnectionException(LastuserResourceException):
    pass


class LastuserTokenAuthException(LastuserException):
    pass


def randomstring():
    """Returns a random UUID for use as a state token for CSRF protection"""
    return str(uuid.uuid4())


def resource_auth_error(message):
    return Response(message, 401,
        {'WWW-Authenticate': 'Bearer realm="Token Required"'})


class UserInfo(object):
    """
    User info object that is inserted into the context variable container (flask.g)
    """
    def __init__(self, token, token_type, token_scope, userid,
            username, fullname, email=None,
            permissions=(), organizations=None):
        self.token = token
        self.token_type = token_type
        self.token_scope = token_scope
        self.userid = userid
        self.username = username
        self.fullname = fullname
        self.email = email
        self.permissions = permissions
        self.organizations = organizations


class UserManagerBase(object):
    """
    Base class for database-aware user managers.
    """
    def load_user(self, userid, create=False):
        raise NotImplementedError("Not implemented in the base class")

    def load_user_by_username(self, username):
        raise NotImplementedError("Not implemented in the base class")

    def make_userinfo(self, user):
        raise NotImplementedError("Not implemented in the base class")

    def load_user_userinfo(self, userinfo, access_token, update=False):
        raise NotImplementedError("Not implemented in the base class")

    def token_auth(self, resource='*', header_only=False):
        if 'Authorization' in request.headers:
            token_match = auth_bearer_re.search(request.headers['Authorization'])
            if token_match:
                token = token_match.group(1)
            else:
                # Unrecognized Authorization header
                raise LastuserTokenAuthException("A Bearer token is required in the Authorization header.")
            if 'access_token' in request.values:
                raise LastuserTokenAuthException("Access token specified in both header and body.")
        elif not header_only:
            # Is there an access token in the form or query?
            token = request.values.get('access_token')
        else:
            return

        if not token:
            return

        if resource == '*':
            cache_key = 'lastuser/tokenverify/{token}'.format(token=token)
        else:
            cache_key = 'lastuser/tokenverify/{token}/{resource}'.format(token=token, resource=resource)
        result = None

        config = current_app.lastuser_config

        if config['cache']:
            result = config['cache'].get(cache_key)
        if result is None:
            result = self.lastuser._lastuser_api_call(config['tokenverify_endpoint'],
                resource=resource, access_token=token)
        if config['cache']:
            config['cache'].set(cache_key, result, timeout=300)
        if result['status'] == 'error' or 'userinfo' not in result:
            raise LastuserTokenAuthException("Invalid token.")
        elif result['status'] == 'ok':
            # All okay.
            # If the user is unknown, make a new user. If the user is known, don't update scoped data
            user = self.load_user_userinfo(result['userinfo'], access_token=None, update=False)
            return user

    def before_request(self):
        """
        Listener that is called at the start of each request. Responsible for
        setting current_auth.user and current_auth.lastuserinfo
        """
        user = None
        token_error = None
        add_auth_attribute('lastuserinfo', None)
        user_from_token = False

        add_auth_attribute('cookie', {})

        config = current_app.lastuser_config

        # Migrate data from Flask cookie session
        if 'lastuser_sessionid' in session:
            current_auth.cookie['sessionid'] = session.pop('lastuser_sessionid')
            current_auth.cookie['updated_at'] = utcnow().isoformat()
        if 'lastuser_userid' in session:
            current_auth.cookie['userid'] = session.pop('lastuser_userid')
            current_auth.cookie['updated_at'] = utcnow().isoformat()

        # If we have a Lastuser cookie, it overrides the user tokens in the session
        if 'lastuser' in request.cookies:
            try:
                lastuser_cookie, lastuser_cookie_headers = config['serializer'].loads(
                    request.cookies['lastuser'], return_header=True)
            except itsdangerous.BadSignature:
                lastuser_cookie = {}
            add_auth_attribute('cookie', lastuser_cookie)

        # Look for a valid auth token that maps to a user
        try:
            user = self.token_auth(header_only=True)
        except LastuserTokenAuthException as e:
            token_error = e
            user = None
        if user:
            user_from_token = True
        else:
            if config['cache'] and config['use_sessions']:
                # If this app has a cache and sessions aren't explicitly disabled, use sessions
                if 'sessionid' in current_auth.cookie and 'userid' in current_auth.cookie:
                    # We have a sessionid and userid. Load user and verify the session
                    user = self.load_user(current_auth.cookie['userid'])
                    if not user:
                        # Are we in a subdomain with a parent domain cookie, with a completely
                        # new user? Try loading this user from Lastuser and obtaining an
                        # access_token if we're a trusted client.
                        user = self.lastuser.login_from_cookie(current_auth.cookie['userid'])
                    if user:
                        cache_key = ('lastuser/session/' + current_auth.cookie['sessionid']).encode('utf-8')
                        sessiondata = config['cache'].get(cache_key)
                        fresh_data = False
                        if not sessiondata:
                            sessiondata = self.lastuser.session_verify(
                                current_auth.cookie['sessionid'], user)
                            fresh_data = True
                        if sessiondata.get('active'):
                            config['cache'].set(cache_key, sessiondata, timeout=300)
                            if fresh_data:
                                signal_user_session_refreshed.send(user)
                        else:
                            config['cache'].delete(cache_key)
                            user = None
                            if fresh_data:
                                signal_user_session_expired.send(user)
            elif 'userid' in current_auth.cookie:
                user = self.load_user(current_auth.cookie['userid'])
                if not user:
                    # As above, try to create user record
                    user = self.lastuser.login_from_cookie(current_auth.cookie['userid'])

        if not user:
            current_auth.cookie.pop('userid', None)
            current_auth.cookie.pop('sessionid', None)
            current_auth.cookie['updated_at'] = utcnow().isoformat()

        add_auth_attribute('user', user)
        g.user = user  # XXX: Deprecated, for backward compatibility only
        if user:
            add_auth_attribute('access_scope', ['*'])  # TODO: In future, restrict to access token's scope
            add_auth_attribute('lastuserinfo', self.make_userinfo(user))
            if not user_from_token:
                if current_auth.cookie.get('userid') != user.userid:
                    # Merged account loaded. Switch over
                    current_auth.cookie['userid'] = user.userid
                    current_auth.cookie['updated_at'] = utcnow().isoformat()

        # This will be set to True by the various login_required handlers downstream
        add_auth_attribute('login_required', False)
        signal_user_looked_up.send(current_auth.user)

        if token_error is not None:
            return resource_auth_error(str(token_error))

    def login_listener(self, userinfo, token):
        """
        Listener that is called when a user logs in. ``userinfo`` and ``token``
        are dictionaries containing data received from Lastuser.
        """
        self.before_request()

    def update_teams(self, user):
        """
        Update team data from this user's access token, if applicable.
        """
        pass

    def user_emails(self, user):
        """
        Retrieve all known email addresses for the given user.
        """
        result = self.lastuser.call_resource('email', all=1,
            _token=user.lastuser_token,
            _token_type=user.lastuser_token_type)

        if result.get('status') == 'ok':
            return result['result']['all']
        else:
            return []

    def user_phones(self, user):
        """
        Retrieve all known phone numbers for the given user.
        """
        result = self.lastuser.call_resource('phone', all=1,
            _token=user.lastuser_token,
            _token_type=user.lastuser_token_type)

        if result.get('status') == 'ok':
            return result['result']['all']
        else:
            return []


class Lastuser(object):
    """
    Flask extension for Lastuser
    """
    def __init__(self, app=None, cache=None):
        self.cache = cache

        self._login_handler = None
        self._redirect_uri_name = None
        self._auth_error_handler = None
        self.usermanager = None

        self.resources = OrderedDict()

        if app is not None:
            self.init_app(app)

    def _init_app_lastuser_config(self, app):
        # Used by init_app and init_cache to create empty config
        if not hasattr(app, 'lastuser_config'):
            app.lastuser_config = {}
        app.lastuser_config.setdefault('external_resources', {})
        app.lastuser_config.setdefault('cache', None)

        app.lastuser_config.setdefault('lastuser_server', None)
        app.lastuser_config.setdefault('auth_endpoint', None)
        app.lastuser_config.setdefault('token_endpoint', None)
        app.lastuser_config.setdefault('client_id', None)
        app.lastuser_config.setdefault('client_secret', None)
        app.lastuser_config.setdefault('use_sessions', True)

    def init_cache(self, app, cache):
        self._init_app_lastuser_config(app)
        app.lastuser_config['cache'] = cache

    def init_app(self, app):
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['lastuser'] = self
        app.login_manager = self
        self._init_app_lastuser_config(app)

        # TODO: Implement `self._load_user` that does the same as `before_request`

        if 'cache' in app.extensions and isinstance(app.extensions['cache'], dict):
            for c in list(app.extensions['cache'].keys()):
                if c.with_jinja2_ext:
                    # Main application cache. Use it.
                    self.init_cache(app, c)
                    break

        app.lastuser_config['lastuser_server'] = app.config['LASTUSER_SERVER']
        app.lastuser_config['auth_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_AUTH', 'auth')
        app.lastuser_config['token_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_TOKEN', 'token')
        app.lastuser_config['logout_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_LOGOUT', 'logout')
        app.lastuser_config['login_beacon_iframe_endpoint'] = app.config.get(
            'LASTUSER_LOGIN_BEACON_IFRAME', 'api/1/login/beacon.html')

        app.lastuser_config['syncresources_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_REGISTER_RESOURCE', 'api/1/resource/sync')
        app.lastuser_config['tokenverify_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_TOKENVERIFY', 'api/1/token/verify')
        app.lastuser_config['tokengetscope_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_TOKENGETSCOPE', 'api/1/token/get_scope')
        app.lastuser_config['getuser_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_GETUSER', 'api/1/user/get')
        app.lastuser_config['getusers_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_GETUSER', 'api/1/user/getusers')
        app.lastuser_config['getuser_userid_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_GETUSER_USERID', 'api/1/user/get_by_userid')
        app.lastuser_config['getuser_userids_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_GETUSER_USERIDS', 'api/1/user/get_by_userids')
        app.lastuser_config['getuser_autocomplete_endpoint'] = app.config.get(
            'LASTUSER_ENDPOINT_USER_AUTOCOMPLETE', 'api/1/user/autocomplete')
        app.lastuser_config['client_id'] = app.config['LASTUSER_CLIENT_ID']
        app.lastuser_config['client_secret'] = app.config['LASTUSER_CLIENT_SECRET']
        app.lastuser_config['use_sessions'] = app.config.get('LASTUSER_USE_SESSIONS', True)

        # Setup cookie serializer
        app.lastuser_config['serializer'] = itsdangerous.JSONWebSignatureSerializer(
            app.config.get('LASTUSER_SECRET_KEY') or app.config['SECRET_KEY'])

        # Register known external resources provided by Lastuser itself
        with app.app_context():  # Required by `self.endpoint_url`
            self.external_resource(app, 'id', self.endpoint_url('api/1/id'), 'GET')
            self.external_resource(app, 'email', self.endpoint_url('api/1/email'), 'GET')
            self.external_resource(app, 'email/add', self.endpoint_url('api/1/email/add'), 'POST')
            self.external_resource(app, 'email/remove', self.endpoint_url('api/1/email/remove'), 'POST')
            self.external_resource(app, 'phone', self.endpoint_url('api/1/phone'), 'GET')
            self.external_resource(app, 'phone/add', self.endpoint_url('api/1/phone/add'), 'POST')
            self.external_resource(app, 'phone/remove', self.endpoint_url('api/1/phone/remove'), 'POST')
            self.external_resource(app, 'organizations', self.endpoint_url('api/1/organizations'), 'GET')
            self.external_resource(app, 'teams', self.endpoint_url('api/1/teams'), 'GET')
            self.external_resource(app, 'session/verify', self.endpoint_url('api/1/session/verify'), 'POST')

        app.before_request(self.before_request)
        app.after_request(self.after_request)

    def init_usermanager(self, um):
        self.usermanager = um
        um.lastuser = weakref.proxy(self)

    def before_request(self):
        add_auth_attribute('lastuser', self)
        if self.usermanager:
            self.usermanager.before_request()

    def after_request(self, response):
        """
        Save login status cookie and tell proxies to not publicly cache pages.
        If you are using Flask-Lastuser, your app takes user logins, and pages
        for a user should not be cached by proxies.

        Warning: this will also be applied to static pages if served through
        your app. Static resources should be served by downstream servers
        without involving Python code.
        """
        # FIXME: Only add these headers if there's a user logged in
        if 'Expires' not in response.headers:
            response.headers['Expires'] = 'Fri, 01 Jan 1990 00:00:00 GMT'
        if 'Cache-Control' in response.headers:
            if 'private' not in response.headers['Cache-Control'] and 'public' not in response.headers['Cache-Control']:
                response.headers['Cache-Control'] = 'private, ' + response.headers['Cache-Control']
        else:
            response.headers['Cache-Control'] = 'private'

        # Set login cookie, but only if there's a user or an existing login cookie
        # This prevents sending a cookie during an API call with no incoming cookie
        # There won't be a current_auth.cookie if this is a 400 Bad Request
        if request_has_auth() and hasattr(current_auth, 'cookie'):
            if 'lastuser' in request.cookies or current_auth.cookie:
                expires = utcnow() + timedelta(days=365)
                response.set_cookie('lastuser',
                    value=current_app.lastuser_config['serializer'].dumps(current_auth.cookie, header_fields={'v': 1}),
                    max_age=31557600,                                         # Keep this cookie for a year.
                    expires=expires,                                          # Expire one year from now.
                    domain=current_app.config.get('LASTUSER_COOKIE_DOMAIN'),  # Place cookie in master domain.
                    secure=current_app.config['SESSION_COOKIE_SECURE'],       # HTTPS cookie if session is too.
                    httponly=True)                                            # Don't allow reading this from JS.
        return response

    def requires_login(self, f):
        """
        Decorator for functions that require login.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            add_auth_attribute('login_required', True)
            if hasattr(current_auth, 'lastuserinfo') and current_auth.lastuserinfo is None:
                if not self._login_handler:
                    abort(403)
                return redirect(url_for(self._login_handler.__name__,
                    next=get_current_url()))
            signal_before_wrapped_view.send(f)
            return f(*args, **kwargs)
        return decorated_function

    def permissions(self):
        """
        Return all permissions available to user.
        """
        return current_auth.lastuserinfo is not None and current_auth.lastuserinfo.permissions or []

    def has_permission(self, permission):
        """
        Returns True if the current user has the specified permission.

        :param permission: Permission to check for. If multiple permissions are passed,
            any of them may match.
        :type permission: str, list, tuple, set
        """
        if is_collection(permission):
            return bool(set(permission) & set(self.permissions()))
        else:
            return permission in self.permissions()

    def requires_permission(self, permission):
        """
        Decorator that checks if the user has a certain permission from Lastuser. Uses
        :meth:`has_permission` to check if the permission is available.
        """
        def inner(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                add_auth_attribute('login_required', True)
                if current_auth.lastuserinfo is None:
                    if not self._login_handler:
                        abort(403)
                    return redirect(url_for(self._login_handler.__name__,
                        next=get_current_url()))
                if not self.has_permission(permission):
                    abort(403)
                signal_before_wrapped_view.send(f)
                return f(*args, **kwargs)
            return decorated_function
        return inner

    def requires_scope(self, *scope):
        """
        Decorator that checks if the user's access token includes the specified scope.
        If not present, it redirects the user to Lastuser to request access rights.
        """
        def inner(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                add_auth_attribute('login_required', True)
                # If the user's not logged in, log them in
                if current_auth.lastuserinfo is None:
                    if not self._login_handler:
                        abort(403)
                    return redirect(url_for(self._login_handler.__name__,
                        next=get_current_url()))
                # If the user is logged in, check if they have the required scope.
                # If not, send them off to Lastuser for the additional scope.
                existing = current_auth.lastuserinfo.token_scope.split(' ')
                for item in scope:
                    if item not in existing:
                        required = set(self._login_handler().get('scope', 'id').split(' '))
                        required.update(scope)
                        return self._login_handler_internal(scope=' '.join(required), next=get_current_url())
                signal_before_wrapped_view.send(f)
                return f(*args, **kwargs)
            return decorated_function
        return inner

    def login_handler(self, f):
        """
        Decorator for login handler route.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            add_auth_attribute('login_required', True)
            data = f(*args, **kwargs)
            metarefresh = getbool(request.args.get('metarefresh'))
            if 'cookietest' in request.args:
                next = get_next_url()
            else:
                next = data.get('next') or get_next_url(referrer=True)
            if session.new and 'cookietest' not in request.args:
                # Check if the user's browser supports cookies
                session['cookies'] = True
                # Reconstruct current URL with ?cookietest=1 or &cookietest=1 appended
                url_parts = urlsplit(request.url)
                if url_parts.query:
                    return redirect(request.url + '&cookietest=1&next=' + urllib.parse.quote(next))
                else:
                    return redirect(request.url + '?cookietest=1&next=' + urllib.parse.quote(next))
            else:
                if session.new:
                    # No support for cookies. Abort login
                    return self._auth_error_handler('no_cookies',
                        error_description="Your browser must accept cookies for you to login.",
                        error_uri="")
                else:
                    # The 'cookies' key is not needed anymore
                    session.pop('cookies', None)

            scope = data.get('scope', 'id')
            message = data.get('message') or request.args.get('message')
            if isinstance(message, str):
                message = message.encode('utf-8')
            return self._login_handler_internal(scope, next, message, metarefresh)
        self._login_handler = f
        return decorated_function

    def _login_handler_internal(self, scope, next, message=None, metarefresh=False):
        if not self._redirect_uri_name:
            raise LastuserConfigException("No authorization handler defined")
        config = current_app.lastuser_config
        session['lastuser_state'] = randomstring()
        session['lastuser_redirect_uri'] = url_for(self._redirect_uri_name,
                next=next, _external=True)
        # Discard currently logged in user
        current_auth.cookie.pop('sessionid', None)
        current_auth.cookie.pop('userid', None)
        current_auth.cookie['updated_at'] = utcnow().isoformat()
        login_redirect_url = '%s?%s' % (urljoin(config['lastuser_server'], config['auth_endpoint']),
            urllib.parse.urlencode([
                ('client_id', config['client_id']),
                ('response_type', 'code'),
                ('scope', scope),
                ('state', session['lastuser_state']),
                ('redirect_uri', session['lastuser_redirect_uri']),
                ] + ([('message', message)] if message else [])))
        if not metarefresh:
            return redirect(login_redirect_url)
        else:
            return Response(
                '''<!DOCTYPE html>
                <html><head><title>Redirecting…</title><meta http-equiv="refresh" content="0; {url}" /></head>
                <body><a href="{url}">Logging you in…</a></body></html>'''.format(url=login_redirect_url),
                200, {
                    'Expires': 'Fri, 01 Jan 1990 00:00:00 GMT',
                    'Cache-Control': 'private, no-cache'
                    })

    def logout_handler(self, f):
        """
        Decorator for logout handler route.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            add_auth_attribute('login_required', True)
            next = f(*args, **kwargs)
            add_auth_attribute('lastuserinfo', None)
            current_auth.cookie.pop('sessionid', None)
            current_auth.cookie.pop('userid', None)
            current_auth.cookie['updated_at'] = utcnow().isoformat()
            if not (next.startswith('http:') or next.startswith('https:')):
                next = urljoin(request.url_root, next)
            config = current_app.lastuser_config
            return Response('''<!DOCTYPE html>
                <html><head><meta http-equiv="refresh" content="0; {url}" /></head>
                <body><a href="{url}">Logging you out…</a></body></html>'''.format(
                url=urljoin(config['lastuser_server'], config['logout_endpoint']) + '?client_id=%s&next=%s'
                % (urllib.parse.quote(config['client_id']), urllib.parse.quote(next))),
                200, {
                    'Expires': 'Fri, 01 Jan 1990 00:00:00 GMT',
                    'Cache-Control': 'private, no-cache'
                    })

        return decorated_function

    def auth_handler(self, f):
        """
        Set the login cookies.

        This method closely resembles :meth:`login_from_cookie`.
        """
        @wraps(f)
        def decorated_function(*args, **kw):
            add_auth_attribute('login_required', True)
            # Step 1: Validations
            # Validation 1: Check if there is an error handler
            if not self._auth_error_handler:
                raise LastuserConfigException("No authorization error handler")
            # Validation 2: Check for CSRF attacks
            state = request.args.get('state')
            if state is None or state != session.get('lastuser_state'):
                return self._auth_error_handler(error='csrf_invalid')
            session.pop('lastuser_state', None)
            # Validation 3: Check if request for auth code was successful
            if 'error' in request.args:
                return self._auth_error_handler(
                    error=request.args['error'],
                    error_description=request.args.get('error_description'),
                    error_uri=request.args.get('error_uri'))
            # Validation 4: Check if we got an auth code
            code = request.args.get('code')
            if not code:
                return self._auth_error_handler(error='code_missing')
            # Validations done

            config = current_app.lastuser_config

            # Step 2: Get the auth token
            r = requests.post(urljoin(config['lastuser_server'], config['token_endpoint']),
                auth=(config['client_id'], config['client_secret']),
                headers={'Accept': 'application/json'},
                data={'code': code,
                      'redirect_uri': session.get('lastuser_redirect_uri'),
                      'grant_type': 'authorization_code',
                      'scope': self._login_handler().get('scope', '')})
            result = r.json()

            # Step 2.1: Remove temporary session variables
            session.pop('lastuser_redirect_uri', None)

            # Step 3: Check if auth token was refused
            if 'error' in result:
                return self._auth_error_handler(
                    error=result['error'],
                    error_description=result.get('error_description'),
                    error_uri=result.get('error_uri'))

            # Step 4.1: All good. Relay any messages we received
            if 'messages' in result:
                for item in result['messages']:
                    flash(item['message'], item['category'])
            # Step 4.2: Save token info
            token = {
                'access_token': result.get('access_token'),
                'token_type': result.get('token_type'),
                'scope': result.get('scope'),
                }
            # Step 4.3: Save user info received
            userinfo = result.get('userinfo', {})
            if 'sessionid' in userinfo and config['use_sessions']:
                # Remove sessionid from userinfo as it's session-specific data
                # while the rest of userinfo is longterm
                current_auth.cookie['sessionid'] = userinfo.pop('sessionid')
            current_auth.cookie['userid'] = userinfo['userid']
            current_auth.cookie['updated_at'] = utcnow().isoformat()
            # Step 4.4: Connect to a user manager if there is one
            if self.usermanager:
                self.usermanager.login_listener(userinfo, token)
            # Step 4.5: Connect to auth handler in user code
            return f(*args, **kw)
        self._redirect_uri_name = f.__name__
        return decorated_function

    def login_from_cookie(self, userid):
        """
        This user has just showed up with a cookie set by lastuser, but with no
        internal record. We treat it like a login now.

        This method closely resembles :meth:`auth_handler`.
        """
        config = current_app.lastuser_config
        r = requests.post(urljoin(config['lastuser_server'], config['token_endpoint']),
            auth=(config['client_id'], config['client_secret']),
            headers={'Accept': 'application/json'},
            data={'userid': userid,
                  'grant_type': 'client_credentials',
                  'scope': self._login_handler().get('scope', '')})
        result = r.json()

        if 'error' in result:
            # Lastuser doesn't like us. Maybe we're not a trusted app. Ignore and move on.
            return

        if 'messages' in result:
            for item in result['messages']:
                flash(item['message'], item['category'])
        token = {
            'access_token': result.get('access_token'),
            'token_type': result.get('token_type'),
            'scope': result.get('scope'),
            }
        userinfo = result['userinfo']
        if 'sessionid' in userinfo and config['use_sessions']:
            current_auth.cookie['sessionid'] = userinfo.pop('sessionid')
        current_auth.cookie['userid'] = userinfo['userid']
        current_auth.cookie['updated_at'] = utcnow().isoformat()
        if self.usermanager:
            return self.usermanager.login_listener(userinfo, token)

    def auth_error_handler(self, f):
        """
        Handler for authorization errors
        """
        @wraps(f)
        def decorated_function(error, error_description=None, error_uri=None):
            return f(error, error_description, error_uri)
        self._auth_error_handler = f
        return decorated_function

    def notification_handler(self, f):
        """
        Handler for service requests from Lastuser, used to notify of new
        resource access tokens and user info changes.
        """
        @wraps(f)
        def decorated_function():
            # Step 1. Only accept POST requests
            if request.method != 'POST':
                abort(405)
            # Step 2. request.form should have at least 'user' and 'changes' keys
            if not ('userid' in request.form and 'changes' in request.form):
                abort(400)
            # Step 3. Is it a logout request?
            if 'logout' in request.form['changes']:
                if self.cache and 'sessionid' in request.form:
                    self.cache.delete(('lastuser/session/' + request.form['sessionid']).encode('utf-8'))
            # Step 4. Look up user account locally. It has to exist
            user = self.usermanager.load_user(request.form['userid'])
            if not user:
                abort(400)
            # Step 5. Ask Lastuser for updated information on this user
            user = self.update_user(user)
            f(user)
            return jsonify({'status': 'ok'})
        return decorated_function

    def endpoint_url(self, endpoint):
        """
        Returns the full URL to a given endpoint path on the current Lastuser server.
        """
        return urljoin(current_app.lastuser_config['lastuser_server'], endpoint)

    def _lastuser_api_call(self, endpoint, method='POST', **kwargs):
        config = current_app.lastuser_config
        r = {'GET': requests.get,
            'POST': requests.post}[method](
                self.endpoint_url(endpoint),
                auth=(config['client_id'], config['client_secret']),
                data=kwargs, headers={'Accept': 'application/json'})
        if r.status_code in (400, 500, 401):
            raise LastuserApiException("Call to %s returned %d" % (endpoint, r.status_code))
        elif r.status_code in (200, 201, 202, 203):
            return r.json()
        else:
            raise LastuserApiException("Call to %s returned unknown status %d and response %s " % (
                endpoint, r.status_code, r.text))

    def sync_resources(self):
        return self._lastuser_api_call(current_app.lastuser_config['syncresources_endpoint'],
            resources=json.dumps(self.resources))

    def resource_handler(self, name, description="", siteresource=False):
        """
        Decorator for resource handlers. Verifies tokens and passes info on
        the user and calling client.
        """
        def inner(f):
            @wraps(f)
            def decorated_function(*args, **kw):
                return
                # FIXME: resource_handler no longer works
            self.resources[name] = {
                'name': name,
                'description': description,
                'siteresource': siteresource
                }
            return decorated_function
        return inner

    # TODO: Map to app user if present. Check with UserManager
    def getuser(self, name):
        result = self._lastuser_api_call(current_app.lastuser_config['getuser_endpoint'], name=name)
        if (not result) or ('error' in result):
            return None
        else:
            return result

    # TODO: Map to app users if present. Check with UserManager
    def getusers(self, names):
        result = self._lastuser_api_call(current_app.lastuser_config['getusers_endpoint'], name=names)
        if (not result) or ('error' in result):
            return None
        else:
            return result['results']

    # TODO: Map to app user if present. Check with UserManager
    def getuser_by_userid(self, userid):
        result = self._lastuser_api_call(current_app.lastuser_config['getuser_userid_endpoint'], userid=userid)
        if (not result) or ('error' in result):
            return None
        else:
            return result

    # TODO: Map to app user if present. Check with UserManager
    def getuser_by_userids(self, userids):
        result = self._lastuser_api_call(current_app.lastuser_config['getuser_userids_endpoint'], userid=userids)
        if (not result) or ('error' in result):
            return None
        else:
            return result['results']

    def external_resource(self, app, name, endpoint, method):
        """
        Register an external resource.
        """
        if method not in ['GET', 'PUT', 'POST', 'DELETE']:
            raise LastuserException("Unknown HTTP method '%s'" % method)
        app.lastuser_config['external_resources'][name] = {'endpoint': endpoint, 'method': method}

    def call_resource(self, name, headers=None, data=None, files=None,
                      _raw=False, _token=None, _token_type=None, **kw):
        """
        Call an external resource.
        """
        resource_details = current_app.lastuser_config['external_resources'][name]

        if _token is None:
            if not hasattr(current_auth, 'lastuserinfo') or not current_auth.lastuserinfo:
                raise LastuserResourceException("No access token available")
            _token = current_auth.lastuserinfo.token
            _token_type = current_auth.lastuserinfo.token_type

        if _token_type is None:
            raise LastuserResourceException("Token type not provided")
        if _token_type != 'bearer':
            raise LastuserResourceException("Unsupported token type")

        if headers is None:
            headers = {}
        else:
            # Make a copy before modifying
            headers = dict(headers)
        headers['Authorization'] = 'Bearer %s' % _token

        try:
            if resource_details['method'] == 'GET':
                r = requests.get(resource_details['endpoint'], headers=headers, params=kw)
            else:
                r = requests.request(resource_details['method'], resource_details['endpoint'],
                    headers=headers, data=data if data is not None else kw, files=files)
        except requests.exceptions.RequestException as e:
            raise LastuserResourceConnectionException("Could not connect to the server. Connection error: %s" % e)
        # Parse the result
        if r.status_code not in (200, 201, 202, 203):
            # XXX: What other status codes could we possibly get from a REST call?
            raise LastuserResourceException("Resource returned status %d" % r.status_code)
        if _raw:
            return r
        else:
            return (r.json()) or r.text

    def user_emails(self, user):
        """
        Retrieve all known email addresses for the given user.
        """
        # TODO: If this is ever cached, provide a way to flush cache
        return self.usermanager.user_emails(user)

    def teams(self, user=None):
        """
        All teams the user has access to.
        """
        if user:
            token = user.lastuser_token
            token_type = user.lastuser_token_type
        else:
            token = token_type = None

        result = self.call_resource('teams',
            _token=token, _token_type=token_type)

        if result['status'] == 'ok':
            return result['result']['teams']
        else:
            return []

    def session_verify(self, sessionid, user=None):
        """
        Verify the user's session.
        """
        if user:
            token = user.lastuser_token
            token_type = user.lastuser_token_type
        else:
            token = token_type = None

        try:
            result = self.call_resource('session/verify', sessionid=sessionid,
                _token=token, _token_type=token_type)

            if result['status'] == 'ok':
                return result['result']
        except LastuserResourceConnectionException:
            # Server not reachable? May be an interim error, so don't knock off the user already
            return {'active': True}
        except LastuserResourceException:
            pass

        return {'active': False}

    def update_user(self, user):
        """
        Update user details from Lastuser.
        """
        result = self.call_resource('id', all=1,
            _token=user.lastuser_token,
            _token_type=user.lastuser_token_type)
        if result.get('status') == 'ok':
            userinfo = result['result']
            user = self.usermanager.load_user_userinfo(userinfo, access_token=None, update=True)
            self.usermanager.update_teams(user)
            user.merge_accounts()
        return user


# Compatibility name
LastUser = Lastuser
