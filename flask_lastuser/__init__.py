# -*- coding: utf-8 -*-

from __future__ import absolute_import
from functools import wraps
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict
import uuid
import urlparse
import requests
import urllib
import re
import weakref
from coaster.views import get_current_url, get_next_url

from flask import session, g, redirect, url_for, request, flash, abort, Response, jsonify

from ._version import *

# Bearer token, as per http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-15#section-2.1
auth_bearer_re = re.compile("^Bearer ([a-zA-Z0-9_.~+/-]+=*)$")


class LastuserConfigException(Exception):
    pass


class LastuserException(Exception):
    pass


class LastuserResourceException(LastuserException):
    pass


def randomstring():
    return unicode(uuid.uuid4())


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

    def load_user_userinfo(self, userinfo, token, update=False):
        raise NotImplementedError("Not implemented in the base class")

    def before_request(self):
        """
        Listener that is called at the start of each request. Responsible for
        setting g.user and g.lastuserinfo
        """
        if session.get('lastuser_userid'):
            user = self.load_user(session['lastuser_userid'])
            if user is None:
                # We'll get here if one of two things happens:
                # 1. This is a dev setup and the local database was deleted or replaced
                # 2. Multiple apps are hosted on one domain and we got a cookie
                #    from another app, but we've never heard of this user before.
                # In either situation, try to create a new user record
                userdata = self.lastuser.getuser_by_userid(session['lastuser_userid'])
                if userdata and userdata.get('type') == 'user':
                    # This is an actual user. Make an account
                    user = self.load_user(session['lastuser_userid'], create=True)
                    user.username = userdata['name']
                    user.fullname = userdata['title']
                    olduser = self.load_user_by_username(userdata['name'])
                    if olduser and olduser != user:
                        olduser.username = None
                    self.db.session.commit()
                else:
                    # No such user. Pop the session
                    session.pop('lastuser_userid', None)
        else:
            user = None

        g.user = user
        if user:
            g.lastuserinfo = self.make_userinfo(user)
        else:
            g.lastuserinfo = None

    def login_listener(self, userinfo, token):
        """
        Listener that is called when a user logs in. ``userinfo`` and ``token``
        are dictionaries containing data received from Lastuser.
        """
        self.before_request()

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

        self.resources = OrderedDict()
        self.external_resources = {}

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.lastuser_server = app.config['LASTUSER_SERVER']
        self.auth_endpoint = app.config.get('LASTUSER_ENDPOINT_AUTH', 'auth')
        self.token_endpoint = app.config.get('LASTUSER_ENDPOINT_TOKEN', 'token')
        self.logout_endpoint = app.config.get('LASTUSER_ENDPOINT_LOGOUT', 'logout')
        self.tokenverify_endpoint = app.config.get('LASTUSER_ENDPOINT_TOKENVERIFY', 'api/1/token/verify')
        self.getuser_endpoint = app.config.get('LASTUSER_ENDPOINT_GETUSER', 'api/1/user/get')
        self.getusers_endpoint = app.config.get('LASTUSER_ENDPOINT_GETUSER', 'api/1/user/getusers')
        self.getuser_userid_endpoint = app.config.get('LASTUSER_ENDPOINT_GETUSER_USERID', 'api/1/user/get_by_userid')
        self.getuser_userids_endpoint = app.config.get('LASTUSER_ENDPOINT_GETUSER_USERIDS', 'api/1/user/get_by_userids')
        self.getorgteams_endpoint = app.config.get('LASTUSER_ENDPOINT_GETORGTEAMS', 'api/1/org/get_teams')
        self.client_id = app.config['LASTUSER_CLIENT_ID']
        self.client_secret = app.config['LASTUSER_CLIENT_SECRET']

        # Register known external resources provided by Lastuser itself
        self.external_resource('id', urlparse.urljoin(self.lastuser_server, 'api/1/id'), 'GET')
        self.external_resource('email', urlparse.urljoin(self.lastuser_server, 'api/1/email'), 'GET')
        self.external_resource('email/add', urlparse.urljoin(self.lastuser_server, 'api/1/email/add'), 'POST')
        self.external_resource('email/remove', urlparse.urljoin(self.lastuser_server, 'api/1/email/remove'), 'POST')
        self.external_resource('phone', urlparse.urljoin(self.lastuser_server, 'api/1/phone'), 'GET')
        self.external_resource('phone/add', urlparse.urljoin(self.lastuser_server, 'api/1/phone/add'), 'POST')
        self.external_resource('phone/remove', urlparse.urljoin(self.lastuser_server, 'api/1/phone/remove'), 'POST')
        self.external_resource('organizations', urlparse.urljoin(self.lastuser_server, 'api/1/organizations'), 'GET')

        self.app.before_request(self.before_request)
        self.app.after_request(self.after_request)

    def init_usermanager(self, um):
        self.usermanager = um
        um.lastuser = weakref.proxy(self)

    def before_request(self):
        if self.usermanager:
            self.usermanager.before_request()

    def after_request(self, response):
        """
        Tell proxies to not publically cache pages.

        Warning: this will also be applied to static pages if served through your app.
        Static resources should be served by upstream servers.
        """
        if 'Expires' not in response.headers:
            response.headers['Expires'] = 'Fri, 01 Jan 1990 00:00:00 GMT'
        if 'Cache-Control' in response.headers:
            if 'private' not in response.headers['Cache-Control'] and 'public' not in response.headers['Cache-Control']:
                response.headers['Cache-Control'] = 'private, ' + response.headers['Cache-Control']
        else:
            response.headers['Cache-Control'] = 'private'
        return response

    def requires_login(self, f):
        """
        Decorator for functions that require login.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if g.lastuserinfo is None:
                if not self._login_handler:
                    abort(403)
                return redirect(url_for(self._login_handler.__name__,
                    next=get_current_url()))
            return f(*args, **kwargs)
        return decorated_function

    def permissions(self):
        """
        Return all permissions available to user.
        """
        return g.lastuserinfo is not None and g.lastuserinfo.permissions or []

    def has_permission(self, permission):
        """
        Returns True if the current user has the specified permission.

        :param permission: Permission to check for. If multiple permissions are passed,
            any of them may match.
        :type permission: string, list/tuple
        """
        if isinstance(permission, (list, tuple)):
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
                if g.lastuserinfo is None:
                    if not self._login_handler:
                        abort(403)
                    return redirect(url_for(self._login_handler.__name__,
                        next=get_current_url()))
                if not self.has_permission(permission):
                    abort(403)
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
                # If the user's not logged in, log them in
                if g.lastuserinfo is None:
                    if not self._login_handler:
                        abort(403)
                    return redirect(url_for(self._login_handler.__name__,
                        next=get_current_url()))
                # If the user is logged in, check if they have the required scope.
                # If not, send them off to Lastuser for the additional scope.
                existing = g.lastuserinfo.token_scope.split(' ')
                for item in scope:
                    if item not in existing:
                        required = set(self._login_handler().get('scope', 'id').split(' '))
                        required.update(scope)
                        return self._login_handler_internal(scope=' '.join(required), next=get_current_url())
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
            if 'cookietest' in request.args:
                next = get_next_url()
            else:
                next = data.get('next') or get_next_url(referrer=True)
            if session.new and 'cookietest' not in request.args:
                # Check if the user's browser supports cookies
                session['cookies'] = True
                # Reconstruct current URL with ?cookietest=1 or &cookietest=1 appended
                url_parts = urlparse.urlsplit(request.url)
                if url_parts.query:
                    return redirect(request.url + '&cookietest=1&next=' + urllib.quote(next))
                else:
                    return redirect(request.url + '?cookietest=1&next=' + urllib.quote(next))
            else:
                if session.new:
                    # No support for cookies. Abort login
                    return self._auth_error_handler('no_cookies',
                        error_description=u"Your browser must accept cookies for you to login.",
                        error_uri="")
                else:
                    # The 'cookies' key is not needed anymore
                    session.pop('cookies', None)

            scope = data.get('scope', 'id')
            return self._login_handler_internal(scope, next)
        self._login_handler = f
        return decorated_function

    def _login_handler_internal(self, scope, next):
        if not self._redirect_uri_name:
            raise LastuserConfigException("No authorization handler defined")
        session['lastuser_state'] = randomstring()
        session['lastuser_redirect_uri'] = url_for(self._redirect_uri_name,
                next=next, _external=True)
        # Discard currently logged in user
        session.pop('lastuser_userid', None)
        return redirect('%s?%s' % (urlparse.urljoin(self.lastuser_server, self.auth_endpoint),
            urllib.urlencode({
                'response_type': 'code',
                'client_id': self.client_id,
                'redirect_uri': session['lastuser_redirect_uri'],
                'scope': scope,
                'state': session['lastuser_state'],
            })))

    def logout_handler(self, f):
        """
        Decorator for logout handler route.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            next = f(*args, **kwargs)
            g.lastuserinfo = None
            session.pop('lastuser_userid', None)
            if not (next.startswith('http:') or next.startswith('https:')):
                next = urlparse.urljoin(request.url_root, next)
            return Response('<!DOCTYPE html>\n'
                '<html><head><meta http-equiv="refresh" content="0; url=%(url)s"></head>\n'
                '<body>Logging you out...</body></html>' % {
                    'url': urlparse.urljoin(self.lastuser_server, self.logout_endpoint) + '?client_id=%s&next=%s'
                % (urllib.quote(self.client_id), urllib.quote(next))})
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

            # Step 2: Get the auth token
            r = requests.post(urlparse.urljoin(self.lastuser_server, self.token_endpoint),
                auth=(self.client_id, self.client_secret),
                data={'code': code,
                      'redirect_uri': session.get('lastuser_redirect_uri'),
                      'grant_type': 'authorization_code',
                      'scope': self._login_handler().get('scope', '')})
            result = r.json() if callable(r.json) else r.json

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
            userinfo = result.get('userinfo')
            session['lastuser_userid'] = userinfo['userid']
            # Step 4.4: Connect to a user manager if there is one
            if self.usermanager:
                self.usermanager.login_listener(userinfo, token)
            # Step 4.5: Connect to auth handler in user code
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
            # Step 3. Look up user account locally. It has to exist
            user = self.usermanager.load_user(request.form['userid'])
            if not user:
                abort(400)
            # Step 4. Ask Lastuser for updated information on this user
            user = self.update_user(user)
            f(user)
            return jsonify({'status': 'ok'})
        return decorated_function

    def endpoint_url(self, endpoint):
        """
        Returns the full URL to a given endpoint path on the current Lastuser server.
        """
        return urlparse.urljoin(self.lastuser_server, endpoint)

    def _lastuser_api_call(self, endpoint, method='POST', **kwargs):
        r = {'GET': requests.get,
            'POST': requests.post}[method](
                self.endpoint_url(endpoint),
                auth=(self.client_id, self.client_secret),
                data=kwargs)
        if r.status_code in (400, 500, 401):
            abort(500)
        elif r.status_code == 200:
            return r.json() if callable(r.json) else r.json

    def resource_handler(self, name, description=None):
        """
        Decorator for resource handlers. Verifies tokens and passes info on
        the user and calling client.
        """
        def resource_auth_error(message):
            return Response(message, 401,
                {'WWW-Authenticate': 'Bearer realm="Token Required" scope="%s"' % name})

        def inner(f):
            @wraps(f)
            def decorated_function(*args, **kw):
                if 'Authorization' in request.headers:
                    token_match = auth_bearer_re.search(request.headers['Authorization'])
                    if token_match:
                        token = token_match.group(1)
                    else:
                        # Unrecognized Authorization header
                        return resource_auth_error(u"A Bearer token is required in the Authorization header.")
                    if 'access_token' in request.args or 'access_token' in request.form:
                        return resource_auth_error(u"Access token specified in both header and body.")
                else:
                    # Checking for access_token in the query
                    token = request.args.get('access_token')
                    if not token:
                        # Checking for access_token in the form
                        token = request.form.get('access_token')
                    if not token:
                        # No token provided in Authorization header or in request parameters
                        return resource_auth_error(u"An access token is required to access this resource.")

                result = self._lastuser_api_call(self.tokenverify_endpoint, resource=name, access_token=token)
                # result should be cached temporarily. Maybe in memcache?
                if result['status'] == 'error':
                    return Response(u"Invalid token.", 403)
                elif result['status'] == 'ok':
                    # All okay.
                    # If the user is unknown, make a new user. If the user is known, don't update scoped data
                    g.user = self.usermanager.load_user_userinfo(result['userinfo'], token=None, update=False)
                    g.lastuserinfo = self.usermanager.make_userinfo(g.user)
                    return f(result, *args, **kw)
            self.resources[name] = {
                'name': name,
                'description': description
                }
            return decorated_function
        return inner

    # TODO: Map to app user if present. Check with UserManager
    def getuser(self, name):
        result = self._lastuser_api_call(self.getuser_endpoint, name=name)
        if (not result) or ('error' in result):
            return None
        else:
            return result

    # TODO: Map to app users if present. Check with UserManager
    def getusers(self, names):
        result = self._lastuser_api_call(self.getusers_endpoint, name=names)
        if (not result) or ('error' in result):
            return None
        else:
            return result['results']

    # TODO: Map to app user if present. Check with UserManager
    def getuser_by_userid(self, userid):
        result = self._lastuser_api_call(self.getuser_userid_endpoint, userid=userid)
        if (not result) or ('error' in result):
            return None
        else:
            return result

    # TODO: Map to app user if present. Check with UserManager
    def getuser_by_userids(self, userids):
        result = self._lastuser_api_call(self.getuser_userid_endpoint, userid=userids)
        if (not result) or ('error' in result):
            return None
        else:
            return result['results']

    def external_resource(self, name, endpoint, method):
        """
        Register an external resource.
        """
        if method not in ['GET', 'PUT', 'POST', 'DELETE']:
            raise LastuserException("Unknown HTTP method '%s'" % method)
        self.external_resources[name] = {'endpoint': endpoint, 'method': method}

    def call_resource(self, name, headers=None, data=None, files=None,
                      _raw=False, _token=None, _token_type=None, **kw):
        """
        Call an external resource.
        """
        resource_details = self.external_resources[name]

        if _token is None:
            if not g.lastuserinfo:
                raise LastuserResourceException("No access token available")
            _token = g.lastuserinfo.token
            _token_type = g.lastuserinfo.token_type

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

        if resource_details['method'] == 'GET':
            r = requests.get(resource_details['endpoint'], headers=headers, params=kw)
        else:
            r = requests.request(resource_details['method'], resource_details['endpoint'],
                headers=headers, data=data if data is not None else kw, files=files)
        # Parse the result
        if r.status_code != 200:
            # XXX: What other status codes could we possibly get from a REST call?
            raise LastuserResourceException("Resource returned status %d." % r.status_code)
        if _raw:
            return r
        else:
            return (r.json() if callable(r.json) else r.json) or r.text

    def user_emails(self, user):
        """
        Retrieve all known email addresses for the given user.
        """
        # TODO: If this is ever cached, provide a way to flush cache
        return self.usermanager.user_emails(user)

    def org_teams(self, org):
        """
        Get a list of teams in the given organization(s).
        """
        data = self._lastuser_api_call(self.getorgteams_endpoint, org=org)
        if data['status'] == 'ok':
            return data['org_teams']
        else:
            return {}

    def update_user(self, user):
        """
        Update user details from Lastuser.
        """
        result = self.call_resource('id', all=1,
            _token=user.lastuser_token,
            _token_type=user.lastuser_token_type)
        if result.get('status') == 'ok':
            userinfo = result['result']
            user = self.usermanager.load_user_userinfo(userinfo, token=None, update=True)
        return user

# Compatibility name
LastUser = Lastuser
