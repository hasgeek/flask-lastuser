#!/bin/sh
pybabel extract -F babel.cfg -k _ -k __ -k ngettext -o flask_lastuser/translations/messages.pot .
pybabel update -D flask_lastuser -i flask_lastuser/translations/messages.pot -d flask_lastuser/translations
