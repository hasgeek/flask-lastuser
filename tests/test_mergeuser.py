# -*- coding: utf-8 -*-

import unittest
from flask import Flask
from flask.ext.lastuser import Lastuser
from flask.ext.lastuser.sqlalchemy import UserManager
from models import db, User, Team, Profile

# -- Tests --------------------------------------------------------------------


class TestCoasterModels(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
        db.init_app(self.app)
        self.ctx = self.app.test_request_context()
        self.ctx.push()
        # These settings are not required for merge user tests
        self.app.config['LASTUSER_SERVER'] = None
        self.app.config['LASTUSER_CLIENT_ID'] = None
        self.app.config['LASTUSER_CLIENT_SECRET'] = None

        self.lastuser = Lastuser(self.app)
        self.lastuser.init_usermanager(UserManager(db, User, Team))

        db.create_all()  # The users_team table doesn't exist until UserManager is inited

        self.create_test_data()

    def tearDown(self):
        db.session.rollback()
        db.drop_all()
        self.ctx.pop()

    def create_test_data(self):
        user1 = User(userid=u"1234567890123456789012", username=u"user1", fullname=u"User 1",
            userinfo={
                'timezone': 'Asia/Kolkata',
                'organizations': {
                    'member': [
                        {
                            'userid': 'qazwsxedcrfvtgbyhnujmi',
                            'name': 'org1',
                            'title': 'Organization 1',
                            },
                        ],
                    'owner': [
                        {
                            'userid': 'qazwsxedcrfvtgbyhnujmi',
                            'name': 'org1',
                            'title': 'Organization 1',
                            },
                        ]
                    }
                })
        user2 = User(userid=u"0987654321098765432109", username=u"user2", fullname=u"User 2",
            userinfo={
                'timezone': 'Asia/Kolkata',
                'organizations': {
                    'member': [
                        {
                            'userid': 'qwertyuiopasdfghjklzxc',
                            'name': 'org2',
                            'title': 'Organization 2',
                            },
                        {
                            'userid': 'mnbvcxzlkjhgfdsapoiuyt',
                            'name': 'org3',
                            'title': 'Organization 3',
                            },
                        ],
                    'owner': [
                        {
                            'userid': 'qwertyuiopasdfghjklzxc',
                            'name': 'org2',
                            'title': 'Organization 2',
                            },
                        {
                            'userid': 'mnbvcxzlkjhgfdsapoiuyt',
                            'name': 'org3',
                            'title': 'Organization 3',
                            },
                        ]
                    }
                })
        user3 = User(userid=u"1234567890987654321234", username=u"user3", fullname=u"User 3",
            userinfo={
                'timezone': 'Asia/Kolkata',
                'organizations': {
                    'member': [
                        {
                            'userid': 'mnbvcxzlkjhgfdsapoiuyt',
                            'name': 'org3',
                            'title': 'Organization 3',
                            },
                        {
                            'userid': 'qazwsxedcrfvtgbyhnujmi',
                            'name': 'org1',
                            'title': 'Organization 1',
                            },
                        ],
                    'owner': [
                        {
                            'userid': 'mnbvcxzlkjhgfdsapoiuyt',
                            'name': 'org3',
                            'title': 'Organization 3',
                            },
                        {
                            'userid': 'qazwsxedcrfvtgbyhnujmi',
                            'name': 'org1',
                            'title': 'Organization 1',
                            },
                        ]
                    }
                })

        team1 = Team(userid=u"1324354657687980089786", orgid=u"qazwsxedcrfvtgbyhnujmi",
            title=u"Team 1", users=[user1, user2])
        team2 = Team(userid=u"0897867564534231243546", orgid=u"qwertyuiopasdfghjklzxc",
            title=u"Team 2", users=[user2, user3])
        team3 = Team(userid=u"1324354657687980132435", orgid=u"mnbvcxzlkjhgfdsapoiuyt",
            title=u"Team 3", users=[user3, user1])

        db.session.add_all([user1, user2, user3, team1, team2, team3])
        db.session.flush()

        # Create six profiles (3 users + 3 orgs)
        Profile.update_from_user(user1, db.session)
        Profile.update_from_user(user2, db.session)
        Profile.update_from_user(user3, db.session)

        db.session.commit()

    def test_profiles_exist(self):
        profiles = Profile.query.all()
        # Six profiles (3 users + 3 orgs)
        self.assertEqual(len(profiles), 6)
        self.assertEqual(set([profile.name for profile in profiles]),
            set([u'user1', u'user2', u'user3', u'org1', u'org2', u'org3']))
