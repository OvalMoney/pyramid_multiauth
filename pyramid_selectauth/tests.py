# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
from zope.interface import implementer

import pyramid.authorization
import pyramid.testing

from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.testing import DummyRequest
from pyramid.security import Everyone, Authenticated
from pyramid.exceptions import Forbidden, ConfigurationError
from pyramid.interfaces import IAuthenticationPolicy, IAuthorizationPolicy

from pyramid_selectauth import (SelectableAuthenticationPolicy,
                                create_selectable_authentication_policy,
                                set_selectable_authentication_policy)


#  Here begins various helper classes and functions for the tests.

@implementer(IAuthenticationPolicy)
class BaseAuthnPolicy(object):
    """A do-nothing base class for authn policies."""

    def __init__(self, **kwds):
        self.__dict__.update(kwds)

    def authenticated_userid(self, request):
        return self.unauthenticated_userid(request)

    def unauthenticated_userid(self, request):
        return None  # pragma: nocover

    def effective_principals(self, request):
        principals = [Everyone]
        userid = self.authenticated_userid(request)
        if userid is not None:
            principals.append(Authenticated)
            principals.append(userid)
        return principals

    def remember(self, request, principal):
        return []  # pragma: nocover

    def forget(self, request):
        return []  # pragma: nocover


@implementer(IAuthenticationPolicy)
class TestAuthnPolicyNull(BaseAuthnPolicy):
    """An authn policy that adds "testnull" to the principals,
     but has no unauthenticated_userid"""

    def unauthenticated_userid(self, request):
        return None

    def effective_principals(self, request):
        return [Everyone, "testnull"]  # pragma: nocover


@implementer(IAuthenticationPolicy)
class TestAuthnPolicy1(BaseAuthnPolicy):
    """An authn policy that adds "test1" to the principals."""

    def unauthenticated_userid(self, request):
        return "test1"

    def remember(self, request, principal):
        return [("X-Remember", principal)]

    def forget(self, request):
        return [("X-Forget", "foo")]


@implementer(IAuthenticationPolicy)
class TestAuthnPolicy2(BaseAuthnPolicy):
    """An authn policy that sets "test2" as the username."""

    def unauthenticated_userid(self, request):
        return "test2"


@implementer(IAuthenticationPolicy)
class TestAuthnPolicy3(BaseAuthnPolicy):
    """Authn policy that sets "test3" as the username "test4" in principals."""

    def unauthenticated_userid(self, request):
        return "test3"

    def effective_principals(self, request):
        return [Everyone, Authenticated, "test3", "test4"]


@implementer(IAuthenticationPolicy)
class TestAuthnPolicyUnauthOnly(BaseAuthnPolicy):
    """An authn policy that returns an unauthenticated userid but not an
    authenticated userid, similar to the basic auth policy.
    """

    def authenticated_userid(self, request):
        return None

    def unauthenticated_userid(self, request):
        return "test3"


@implementer(IAuthorizationPolicy)
class TestAuthzPolicyCustom(object):
    def permits(self, context, principals, permission):
        return True  # pragma: nocover

    def principals_allowed_by_permission(self, context, permission):
        raise NotImplementedError()  # pragma: nocover


@implementer(IAuthenticationPolicy)
class CustomPolicy(SelectableAuthenticationPolicy):
    def select_policy(self, request):
        return self._policies[0]


def policy_factory(config):
    """Config include that doesn't do anything."""
    return TestAuthnPolicy3()


def raiseforbidden(request):
    """View that always just raises Forbidden."""
    raise Forbidden()


#  Here begins the actual test cases


class SelectAuthPolicyTests(unittest.TestCase):
    """Testcases for SelectableAuthenticationPolicy and related hooks."""

    def setUp(self):
        self.config = pyramid.testing.setUp(autocommit=False)
        self.request = DummyRequest()

    def tearDown(self):
        pyramid.testing.tearDown()

    def test_basic_select(self):
        policies = [TestAuthnPolicy1(), TestAuthnPolicy2()]
        policy = create_selectable_authentication_policy(self.config, policies)
        self.assertEqual(policy.authenticated_userid(self.request), "test1")
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test1"])

    def test_selected_policy_not_cached_with_dummyrequest(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = create_selectable_authentication_policy(self.config, policies)
        self.assertEqual(policy.unauthenticated_userid(self.request), "test2")
        policies.reverse()
        self.assertEqual(policy.unauthenticated_userid(self.request), "test3")

    def test_selected_policy_cached_with_real_request(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = create_selectable_authentication_policy(self.config, policies)
        self.request.set_property(policy.select_policy, 'sa_selected_policy',
                                  reify=True)
        self.assertEqual(policy.unauthenticated_userid(self.request), "test2")
        policies.reverse()
        self.assertEqual(policy.unauthenticated_userid(self.request), "test2")

    def test_selecting_of_authenticated_userid(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = create_selectable_authentication_policy(self.config, policies)
        self.assertEqual(policy.authenticated_userid(self.request), "test2")

    def test_selecting_of_effective_principals(self):
        policies = [TestAuthnPolicy3(), TestAuthnPolicy2()]
        policy = create_selectable_authentication_policy(self.config, policies)
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test3", "test4"])
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test3", "test4"])
        policies.append(TestAuthnPolicy1())
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test3", "test4"])

    def test_select_of_remember_and_forget(self):
        policies = [TestAuthnPolicy1(), TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = create_selectable_authentication_policy(self.config, policies)
        self.assertEqual(policy.remember(self.request, "ha"),
                         [("X-Remember", "ha")])
        self.assertEqual(policy.forget(self.request),
                         [("X-Forget", "foo")])

    def test_directive(self):
        policy = create_selectable_authentication_policy(self.config)
        self.config.add_selectauth_policy(TestAuthnPolicy1())
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.set_authentication_policy(policy)
        self.config.commit()

        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(policy, SelectableAuthenticationPolicy))
        self.assertEqual(len(policy._policies), 1)
        self.assertEqual(policy.authenticated_userid(self.request),
                         "test1")
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test1"])

    def test_directive_on_includeme(self):
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.add_selectauth_policy(TestAuthnPolicy1())
        self.config.add_selectauth_policy(TestAuthnPolicy2())
        self.config.commit()

        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(policy, SelectableAuthenticationPolicy))
        self.assertEqual(len(policy._policies), 2)
        self.assertEqual(policy.authenticated_userid(self.request),
                         "test1")
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test1"])

    def test_directive_on_includeme_with_factory(self):
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.add_selectauth_policy(policy_factory)
        self.config.commit()

        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(policy, SelectableAuthenticationPolicy))
        self.assertEqual(len(policy._policies), 1)
        self.assertEqual(policy.authenticated_userid(self.request),
                         "test3")
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test3", "test4"])

    def test_set_selectable_authentication_policy_with_directive(self):
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        set_selectable_authentication_policy(self.config)
        self.config.add_selectauth_policy(policy_factory)
        self.config.commit()

        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(policy, SelectableAuthenticationPolicy))
        self.assertEqual(len(policy._policies), 1)
        self.assertEqual(policy.authenticated_userid(self.request),
                         "test3")
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test3", "test4"])

    def test_set_selectable_authentication_policy(self):
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        set_selectable_authentication_policy(self.config, [TestAuthnPolicy3()])
        self.config.commit()

        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(policy, SelectableAuthenticationPolicy))
        self.assertEqual(len(policy._policies), 1)
        self.assertEqual(policy.authenticated_userid(self.request),
                         "test3")
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test3", "test4"])

    def test_directive_mixed_settings(self):
        self.config.add_settings({
            "selectauth.policies":
                "pyramid_selectauth.tests.policy_factory "
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.add_selectauth_policy(TestAuthnPolicy1())
        self.config.add_selectauth_policy(TestAuthnPolicy2())
        self.config.commit()

        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(policy, SelectableAuthenticationPolicy))
        self.assertEqual(len(policy._policies), 3)
        self.assertEqual(policy.authenticated_userid(self.request),
                         "test3")
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test3", "test4"])

    def test_wrong_config(self):
        self.config.add_settings({
            "selectauth.policies": TestAuthnPolicy3()
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        with self.assertRaises(ConfigurationError):
            self.config.include("pyramid_selectauth")

    def test_includeme_custom_class(self):
        self.config.add_settings({
            "selectauth.policy_class": "pyramid_selectauth.tests."
            "CustomPolicy"
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(policy, CustomPolicy))

    def test_includeme_custom_class_doesnt_extend_selectauth(self):
        self.config.add_settings({
            "selectauth.policy_class": "pyramid_selectauth.tests."
            "TestAuthnPolicyNull"
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        with self.assertRaises(ConfigurationError):
            self.config.include("pyramid_selectauth")

    def test_includeme_by_module(self):
        self.config.add_settings({
            "selectauth.policies":
                "pyramid_selectauth.tests.policy_factory "
                "pyramid_selectauth.tests.TestAuthnPolicy2"
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertEqual(len(policy._policies), 2)
        self.assertEqual(policy.unauthenticated_userid(self.request), "test3")
        self.assertEqual(policy.authenticated_userid(self.request), "test3")
        # Check that the forbidden view gets invoked.
        self.config.add_route("index", path="/")
        self.config.add_view(raiseforbidden, route_name="index")
        app = self.config.make_wsgi_app()
        environ = {"PATH_INFO": "/", "REQUEST_METHOD": "GET"}

        def start_response(*args):
            pass

        with self.assertRaises(Forbidden):
            app(environ, start_response)

    def test_includeme_with_list(self):
        self.config.add_settings({
            "selectauth.policies":
                ["pyramid_selectauth.tests.TestAuthnPolicy2",
                 "pyramid_selectauth.tests.TestAuthnPolicy3"]
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        policies = policy.get_policies()
        expected_result = [TestAuthnPolicy2, TestAuthnPolicy3]
        for (obtained, expected) in zip(policies, expected_result):
            self.assertEqual(obtained, expected)

    def test_includeme_with_modules(self):
        self.config.add_settings({
            "selectauth.policies":
                [TestAuthnPolicy2,
                 TestAuthnPolicy3]
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        policies = policy.get_policies()
        expected_result = [TestAuthnPolicy2, TestAuthnPolicy3]
        for (obtained, expected) in zip(policies, expected_result):
            self.assertEqual(obtained, expected)

    def test_includeme_with_policies(self):
        self.config.add_settings({
            "selectauth.policies":
                [TestAuthnPolicy2(),
                 TestAuthnPolicy3()]
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        policies = policy.get_policies()
        expected_result = [TestAuthnPolicy2, TestAuthnPolicy3]
        for (obtained, expected) in zip(policies, expected_result):
            self.assertEqual(obtained, expected)

    def test_includeme_with_factories(self):
        self.config.add_settings({
            "selectauth.policies":
                [TestAuthnPolicy2(),
                 policy_factory]
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        policies = policy.get_policies()
        expected_result = [TestAuthnPolicy2, TestAuthnPolicy3]
        for (obtained, expected) in zip(policies, expected_result):
            self.assertEqual(obtained, expected)

    def test_get_policies(self):
        self.config.add_settings({
            "selectauth.policies":
                "pyramid_selectauth.tests.TestAuthnPolicy2 "
                "pyramid_selectauth.tests.TestAuthnPolicy3",
        })
        self.config.set_authorization_policy(ACLAuthorizationPolicy)
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        policies = policy.get_policies()
        expected_result = [TestAuthnPolicy2, TestAuthnPolicy3]
        for (obtained, expected) in zip(policies, expected_result):
            self.assertEqual(obtained, expected)

    def test_select_first_policy_with_unauthenticated_userid(self):
        policies = [TestAuthnPolicyNull(), TestAuthnPolicy3()]
        policy = create_selectable_authentication_policy(self.config, policies)
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Authenticated, Everyone, "test3", "test4"])

    def test_no_good_policy(self):
        policies = [TestAuthnPolicyNull(), TestAuthnPolicyUnauthOnly()]
        policy = create_selectable_authentication_policy(self.config, policies)
        self.assertEqual(sorted(policy.effective_principals(self.request)),
                         [Everyone])
