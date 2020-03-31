# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import unittest

from flask import Flask, current_app, json

from flask_lastuser import Lastuser
from flask_lastuser.sqlalchemy import UserManager
from mocket import mocketize
from mocket.mockhttp import Entry
from models import Profile, Team, User, db

# -- Tests --------------------------------------------------------------------


class TestMergeUserData(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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
        user1 = User(
            userid="1234567890123456789012",
            username="user1",
            fullname="User 1",
            email='user1@example.com',
            userinfo={
                'timezone': 'Asia/Kolkata',
                'organizations': {
                    'member': [
                        {
                            'userid': 'qazwsxedcrfvtgbyhnujmi',
                            'name': 'org1',
                            'title': 'Organization 1',
                        }
                    ],
                    'owner': [
                        {
                            'userid': 'qazwsxedcrfvtgbyhnujmi',
                            'name': 'org1',
                            'title': 'Organization 1',
                        }
                    ],
                },
            },
        )
        user2 = User(
            userid="0987654321098765432109",
            username="user2",
            fullname="User 2",
            email='user2@example.com',
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
                    ],
                },
            },
        )
        user3 = User(
            userid="1234567890987654321234",
            username="user3",
            fullname="User 3",
            email='user3@example.com',
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
                    ],
                },
            },
        )

        team1 = Team(
            userid="1324354657687980089786",
            orgid="qazwsxedcrfvtgbyhnujmi",
            title="Team 1",
            users=[user1, user2],
        )
        team2 = Team(
            userid="0897867564534231243546",
            orgid="qwertyuiopasdfghjklzxc",
            title="Team 2",
            users=[user2, user3],
        )
        team3 = Team(
            userid="1324354657687980132435",
            orgid="mnbvcxzlkjhgfdsapoiuyt",
            title="Team 3",
            users=[user3, user1],
        )

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
        self.assertEqual(
            {profile.name for profile in profiles},
            {'user1', 'user2', 'user3', 'org1', 'org2', 'org3'},
        )

    def test_team_users(self):
        user1 = User.query.filter_by(userid="1234567890123456789012").one()
        user2 = User.query.filter_by(userid="0987654321098765432109").one()
        user3 = User.query.filter_by(userid="1234567890987654321234").one()

        team1 = Team.query.filter_by(userid="1324354657687980089786").one()
        team2 = Team.query.filter_by(userid="0897867564534231243546").one()
        team3 = Team.query.filter_by(userid="1324354657687980132435").one()

        self.assertTrue(user1.is_active)
        self.assertTrue(user1.is_active)
        self.assertTrue(user1.is_active)

        self.assertEqual(set(team1.users), {user1, user2})
        self.assertEqual(set(team2.users), {user2, user3})
        self.assertEqual(set(team3.users), {user3, user1})


class TestUserMerge(TestMergeUserData):
    def setUp(self):
        super(TestUserMerge, self).setUp()
        user1 = User.query.filter_by(username='user1').one()
        user2 = User.query.filter_by(username='user2').one()
        user2.merge_into(user1)
        # Normally this would be done by Lastuser:
        user1.userinfo['oldids'] = [user2.userid]
        db.session.commit()

        # Update profiles
        Profile.update_from_user(user1, db.session)

        self.user1 = User.query.filter_by(userid="1234567890123456789012").one()
        self.user2 = User.query.filter_by(userid="0987654321098765432109").one()
        self.user3 = User.query.filter_by(userid="1234567890987654321234").one()

        self.team1 = Team.query.filter_by(userid="1324354657687980089786").one()
        self.team2 = Team.query.filter_by(userid="0897867564534231243546").one()
        self.team3 = Team.query.filter_by(userid="1324354657687980132435").one()

    def tearDown(self):
        super(TestUserMerge, self).tearDown()

    def test_merge_removes_username(self):
        self.assertEqual(self.user1.username, 'user1')
        self.assertIsNone(self.user2.username)
        self.assertEqual(self.user3.username, 'user3')

    def test_merge_removes_email(self):
        self.assertEqual(self.user1.email, 'user1@example.com')
        self.assertIsNone(self.user2.email)
        self.assertEqual(self.user3.email, 'user3@example.com')

    def test_user_is_merged(self):
        self.assertFalse(self.user1.is_merged)
        self.assertTrue(self.user2.is_merged)
        self.assertFalse(self.user3.is_merged)

    def test_teams_user2_is_removed(self):
        # Was [user1, user2], but user2 is merged into user1 and so redundant
        self.assertEqual(set(self.team1.users), {self.user1})
        # Was [user2, user3], but user2 is replaced with user1
        self.assertEqual(set(self.team2.users), {self.user1, self.user3})
        # Was and is [user3, user1]. user2 is not involved here
        self.assertEqual(set(self.team3.users), {self.user3, self.user1})

    def test_user_get_username(self):
        user1 = User.get(username='user1')
        user2 = User.get(username='user2')
        user3 = User.get(username='user3')

        self.assertEqual(user1, self.user1)
        self.assertIsNone(user2)  # Username doesn't exist anymore
        self.assertEqual(user3, self.user3)

    @mocketize
    def test_user_get_userid(self):
        # Handler for `user2 = User.get(...)`
        Entry.single_register(
            Entry.POST,
            self.lastuser.endpoint_url(
                current_app.lastuser_config['getuser_userid_endpoint']
            ),
            body=json.dumps(
                {
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
            ),
            headers={'content-type': 'application/json'},
        )

        user1 = User.get(userid="1234567890123456789012")
        user2 = User.get(userid="0987654321098765432109")
        user3 = User.get(userid="1234567890987654321234")

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
