# -*- coding: utf-8 -*-
"""
    flaskext.lastuser
    ~~~~~~~~~~~~~~~~~

    Flask extension for LastUser

    :copyright: (c) 2011 by HasGeek Media LLP.
    :license: BSD, see LICENSE for more details.
"""

from __future__ import absolute_import
from functools import wraps
from base64 import b64encode
import uuid
import urlparse
import httplib2
import urllib

from flask import session, g, redirect, url_for, request, json, flash, abort


class LastUserConfigException(Exception):
    pass

class LastUserException(Exception):
    pass


def randomstring():
    return unicode(uuid.uuid4())


class UserInfo(object):
    """
    User info object that is inserted into the context variable container.
    """
    def __init__(self, userid, username, fullname, email=None, permissions=()):
        self.userid = userid
        self.username = username
        self.fullname = fullname
        self.email = email
        self.permissions = permissions


class LastUser(object):
    """
    Flask extension for LastUser
    """
    def __init__(self, app=None):
        self.app = app

        self._login_handler = None
        self._redirect_uri_name = None
        self._auth_error_handler = None
        self.usermanager = None

        self.lastuser_server = None
        self.auth_endpoint = None
        self.token_endpoint = None
        self.client_id = None
        self.client_secret = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.lastuser_server = app.config['LASTUSER_SERVER']
        self.auth_endpoint = app.config.get('LASTUSER_ENDPOINT_AUTH', 'auth')
        self.token_endpoint = app.config.get('LASTUSER_ENDPOINT_TOKEN', 'token')
        self.logout_endpoint = app.config.get('LASTUSER_ENDPOINT_LOGOUT', 'logout')
        self.client_id = app.config['LASTUSER_CLIENT_ID']
        self.client_secret = app.config['LASTUSER_CLIENT_SECRET']

        self.app.before_request(self.before_request)

    def init_usermanager(self, um):
        self.usermanager = um

    def before_request(self):
        info = session.get('lastuser_userinfo')
        if info is not None:
            userinfo = UserInfo(userid = info.get('userid'),
                                username = info.get('username'),
                                fullname = info.get('fullname'),
                                email = info.get('email'),
                                permissions = info.get('permissions', ()))
            g.lastuserinfo = userinfo
        else:
            g.lastuserinfo = None
        if self.usermanager:
            self.usermanager.before_request()

    def requires_login(self, f):
        """
        Decorator for functions that require login.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if g.lastuserinfo is None:
                if not self._login_handler:
                    abort(403)
                return redirect(url_for(self._login_handler.__name__, next=request.url))
            return f(*args, **kwargs)
        return decorated_function

    def requires_permission(self, permission):
        def inner(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if g.lastuserinfo is None:
                    if not self._login_handler:
                        abort(403)
                    return redirect(url_for(self._login_handler.__name__, next=request.url))
                if permission not in g.lastuserinfo.permissions:
                    abort(403)
                return f(*args, **kwargs)
            return decorated_function
        return inner

    def login_handler(self, f):
        """
        Decorator for login handler route.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = f(*args, **kwargs)
            if not self._redirect_uri_name:
                raise LastUserConfigException("No authorization handler defined")
            session['lastuser_state'] = randomstring()
            session['lastuser_redirect_uri'] = url_for(self._redirect_uri_name,
                    next=request.args.get('next') or request.referrer or None,
                    _external=True)

            return redirect('%s?%s' % (urlparse.urljoin(self.lastuser_server, self.auth_endpoint),
                urllib.urlencode({
                    'response_type': 'code',
                    'client_id': self.client_id,
                    'redirect_uri': session['lastuser_redirect_uri'],
                    'scope': data.get('scope', 'id'),
                    'state': session['lastuser_state'],
                })))
        self._login_handler = f
        return decorated_function

    def logout_handler(self, f):
        """
        Decorator for logout handler route.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            next = f(*args, **kwargs)
            g.lastuserinfo = None
            session.pop('lastuser_userinfo', None)
            if not (next.startswith('http:') or next.startswith('https:')):
                next = urlparse.urljoin(request.url_root, next)
            return redirect(urlparse.urljoin(self.lastuser_server, self.logout_endpoint) + '?client_id=%s&next=%s'
                % (urllib.quote(self.client_id), urllib.quote(next)))
        return decorated_function

    def auth_handler(self, f):
        """
        Set the login cookies.
        """
        @wraps(f)
        def decorated_function(*args, **kw):
            # Step 1: Validations
            # Validation 1: Check if there is an error handler
            if not self._auth_error_handler:
                raise LastUserConfigException("No authorization error handler")
            # Validation 2: Check for CSRF attacks
            state = request.args.get('state')
            if state is None or state != session.get('lastuser_state'):
                return self._auth_error_handler(error='csrf_invalid')
            session.pop('lastuser_state', None)
            # Validation 3: Check if request for auth code was successful
            if 'error' in request.args:
                return self._auth_error_handler(
                    error = request.args['error'],
                    error_description = request.args.get('error_description'),
                    error_uri = request.args.get('error_uri'))
            # Validation 4: Check if we got an auth code
            code = request.args.get('code')
            if not code:
                return self._auth_error_handler(error='code_missing')
            # Validations done

            # Step 2: Get the auth token
            http = httplib2.Http(cache=None, timeout=None, proxy_info=None)
            http_response, http_content = http.request(urlparse.urljoin(self.lastuser_server, self.token_endpoint),
                "POST",
                headers = {'Content-type': 'application/x-www-form-urlencoded',
                           'Authorization': "Basic %s" % b64encode("%s:%s" % (self.client_id, self.client_secret))},
                body = urllib.urlencode({
                    'client_id': self.client_id,
                    'code': code,
                    'redirect_uri': session.get('lastuser_redirect_uri'),
                    'grant_type': 'authorization_code',
                    'scope': self._login_handler().get('scope', '')
                    })
                )

            result = json.loads(http_content)

            # Step 2.1: Remove temporary session variables
            session.pop('lastuser_redirect_uri', None)

            # Step 3: Check if auth token was refused
            if 'error' in result:
                return self._auth_error_handler(
                    error = result['error'],
                    error_description = result.get('error_description'),
                    error_uri = result.get('error_uri'))

            # Step 4.1: All good. Relay any messages we received
            if 'messages' in result:
                for item in result['messages']:
                    flash(item['message'], item['category'])
            # Step 4.2: Save user info received
            userinfo = result.get('userinfo')
            session['lastuser_userinfo'] = userinfo
            if userinfo is not None:
                g.lastuserinfo = UserInfo(userinfo.get('userid'), userinfo.get('username'),
                    userinfo.get('fullname'), userinfo.get('email'))
            # Step 4.3: Connect to a user manager if there is one
            if self.usermanager:
                self.usermanager.login_listener()
            # Step 4.4: Connect to auth handler in user code
            return f(*args, **kw)
        self._redirect_uri_name = f.__name__
        return decorated_function

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
        Handler for service requests from LastUser, used to notify of new
        resource access tokens and user info changes.
        """
        @wraps(f)
        def decorated_function(*args, **kw):
            return f(*args, **kw)
        return decorated_function
