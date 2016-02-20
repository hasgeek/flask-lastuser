0.4.0
-----

* Support for merging user accounts in client apps.
* i18n using Flask-BabelEx (no UI-facing i18n yet, however).
* Switched to login sessions and cache management (optionally disabled).
* New helper methods owner_choices(), owner_of, member_of in UserBase.
* Login beacon endpoint and object availability as g.lastuser.
* Switch to g.lastuser_cookie for cross-domain login cookie.

0.3.14
------

* Set Cache-Control header to 'private' to prevent proxy caching of
  logged-in pages.
* requires_permission and has_permission now accept multiple permissions.
* Userinfo is now stored as a JSON column where available.
* User.phone now returns the primary verified phone number, if available.
* User.pickername returns "fullname (~username)" if username is present.

0.3.13
------

* Start of version history record.
