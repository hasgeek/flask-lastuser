# -*- coding: utf-8 -*-

import unittest
import httpretty
from flask import Flask, json
from flask_lastuser import Lastuser
from flask_lastuser.sqlalchemy import UserManager
from models import db, User, Team, Profile

# -- Tests --------------------------------------------------------------------


class TestMergeUserData(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
        db.init_app(self.app)
        self.ctx = self.app.test_request_context()
        self.ctx.push()
        # These settings are not required for merge user tests
        self.app.config['LASTUSER_SERVER'] = 'http://lastuser.testing'
        self.app.config['LASTUSER_CLIENT_ID'] = 'client_id'
        self.app.config['LASTUSER_CLIENT_SECRET'] = 'client_secret'

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
            email=u'user1@example.com',
            userinfo={
                u'timezone': u'Asia/Kolkata',
                u'organizations': {
                    u'member': [
                        {
                            u'userid': u'qazwsxedcrfvtgbyhnujmi',
                            u'name': u'org1',
                            u'title': u'Organization 1',
                            },
                        ],
                    u'owner': [
                        {
                            u'userid': u'qazwsxedcrfvtgbyhnujmi',
                            u'name': u'org1',
                            u'title': u'Organization 1',
                            },
                        ]
                    }
                })
        user2 = User(userid=u"0987654321098765432109", username=u"user2", fullname=u"User 2",
            email=u'user2@example.com',
            userinfo={
                u'timezone': u'Asia/Kolkata',
                u'organizations': {
                    u'member': [
                        {
                            u'userid': u'qwertyuiopasdfghjklzxc',
                            u'name': u'org2',
                            u'title': u'Organization 2',
                            },
                        {
                            u'userid': u'mnbvcxzlkjhgfdsapoiuyt',
                            u'name': u'org3',
                            u'title': u'Organization 3',
                            },
                        ],
                    u'owner': [
                        {
                            u'userid': u'qwertyuiopasdfghjklzxc',
                            u'name': u'org2',
                            u'title': u'Organization 2',
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
            email=u'user3@example.com',
            userinfo={
                u'timezone': 'Asia/Kolkata',
                u'organizations': {
                    u'member': [
                        {
                            u'userid': u'mnbvcxzlkjhgfdsapoiuyt',
                            u'name': u'org3',
                            u'title': u'Organization 3',
                            },
                        {
                            u'userid': u'qazwsxedcrfvtgbyhnujmi',
                            u'name': u'org1',
                            u'title': u'Organization 1',
                            },
                        ],
                    u'owner': [
                        {
                            u'userid': u'mnbvcxzlkjhgfdsapoiuyt',
                            u'name': u'org3',
                            u'title': u'Organization 3',
                            },
                        {
                            u'userid': u'qazwsxedcrfvtgbyhnujmi',
                            u'name': u'org1',
                            u'title': u'Organization 1',
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


class TestWithoutMerge(TestMergeUserData):
    def test_profiles_exist(self):
        profiles = Profile.query.all()
        # Six profiles (3 users + 3 orgs)
        self.assertEqual(len(profiles), 6)
        self.assertEqual(set([profile.name for profile in profiles]),
            set([u'user1', u'user2', u'user3', u'org1', u'org2', u'org3']))

    def test_team_users(self):
        user1 = User.query.filter_by(userid=u"1234567890123456789012").one()
        user2 = User.query.filter_by(userid=u"0987654321098765432109").one()
        user3 = User.query.filter_by(userid=u"1234567890987654321234").one()

        team1 = Team.query.filter_by(userid=u"1324354657687980089786").one()
        team2 = Team.query.filter_by(userid=u"0897867564534231243546").one()
        team3 = Team.query.filter_by(userid=u"1324354657687980132435").one()

        self.assertTrue(user1.is_active)
        self.assertTrue(user1.is_active)
        self.assertTrue(user1.is_active)

        self.assertEqual(set(team1.users), set([user1, user2]))
        self.assertEqual(set(team2.users), set([user2, user3]))
        self.assertEqual(set(team3.users), set([user3, user1]))


class TestUserMerge(TestMergeUserData):
    def setUp(self):
        super(TestUserMerge, self).setUp()
        user1 = User.query.filter_by(username=u'user1').one()
        user2 = User.query.filter_by(username=u'user2').one()
        user2.merge_into(user1)
        # Normally this would be done by Lastuser:
        user1.userinfo[u'oldids'] = [user2.userid]
        db.session.commit()

        # Update profiles
        Profile.update_from_user(user1, db.session)

        self.user1 = User.query.filter_by(userid=u"1234567890123456789012").one()
        self.user2 = User.query.filter_by(userid=u"0987654321098765432109").one()
        self.user3 = User.query.filter_by(userid=u"1234567890987654321234").one()

        self.team1 = Team.query.filter_by(userid=u"1324354657687980089786").one()
        self.team2 = Team.query.filter_by(userid=u"0897867564534231243546").one()
        self.team3 = Team.query.filter_by(userid=u"1324354657687980132435").one()

        def request_callback(request, uri, headers):
            if 'userid' in request.parsed_body and request.parsed_body['userid'][0] == '0987654321098765432109':
                response = {
                    "status": "ok",
                    "type": "user",
                    "buid": "1234567890123456789012",
                    "userid": "1234567890123456789012",
                    "name": "user1",
                    "title": "User 1",
                    "label": "User 1 (@user1)",
                    "oldids": ['0987654321098765432109'],
                    "timezone": "Asia/Kolkata",
                    }
            else:
                response = {'status': 'error', 'error': 'not_found'}
            return (200, headers, json.dumps(response))

        httpretty.enable()
        httpretty.register_uri(httpretty.POST, self.lastuser.endpoint_url(self.lastuser.getuser_userid_endpoint),
            body=request_callback,
            content_type="application/json")

    def tearDown(self):
        httpretty.disable()
        httpretty.reset()
        super(TestUserMerge, self).tearDown()

    def test_merge_removes_username(self):
        self.assertEqual(self.user1.username, u'user1')
        self.assertEqual(self.user2.username, None)
        self.assertEqual(self.user3.username, u'user3')

    def test_merge_removes_email(self):
        self.assertEqual(self.user1.email, u'user1@example.com')
        self.assertEqual(self.user2.email, None)
        self.assertEqual(self.user3.email, u'user3@example.com')

    def test_user_is_merged(self):
        self.assertFalse(self.user1.is_merged)
        self.assertTrue(self.user2.is_merged)
        self.assertFalse(self.user3.is_merged)

    def test_teams_user2_is_removed(self):
        # Was [user1, user2], but user2 is merged into user1 and so redundant
        self.assertEqual(set(self.team1.users), set([self.user1]))
        # Was [user2, user3], but user2 is replaced with user1
        self.assertEqual(set(self.team2.users), set([self.user1, self.user3]))
        # Was and is [user3, user1]. user2 is not involved here
        self.assertEqual(set(self.team3.users), set([self.user3, self.user1]))

    def test_user_get_username(self):
        user1 = User.get(username=u'user1')
        user2 = User.get(username=u'user2')
        user3 = User.get(username=u'user3')

        self.assertEqual(user1, self.user1)
        self.assertEqual(user2, None)  # Username doesn't exist anymore
        self.assertEqual(user3, self.user3)

    def test_user_get_userid(self):
        user1 = User.get(userid=u"1234567890123456789012")
        user2 = User.get(userid=u"0987654321098765432109")
        user3 = User.get(userid=u"1234567890987654321234")

        self.assertEqual(user1, self.user1)
        self.assertEqual(user2, self.user1)  # Merged, so returns .merged_user()
        self.assertEqual(user3, self.user3)

    def test_profile_merged(self):
        profile1 = Profile.query.filter_by(userid=self.user1.userid).first()
        profile2 = Profile.query.filter_by(userid=self.user2.userid).first()
        profile3 = Profile.query.filter_by(userid=self.user3.userid).first()

        self.assertFalse(profile1.is_merged)
        self.assertTrue(profile2.is_merged)
        self.assertFalse(profile3.is_merged)
