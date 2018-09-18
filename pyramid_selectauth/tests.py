# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
from zope.interface import implementer

import pyramid.authorization
import pyramid.testing
from pyramid.testing import DummyRequest
from pyramid.security import Everyone, Authenticated
from pyramid.exceptions import Forbidden
from pyramid.interfaces import IAuthenticationPolicy, IAuthorizationPolicy

from pyramid_selectauth import SelectableAuthenticationPolicy


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


def testincludeme1(config):
    """Config include that sets up a TestAuthnPolicy1 and a forbidden view."""
    config.set_authentication_policy(TestAuthnPolicy1())

    def forbidden_view(request):
        return "FORBIDDEN ONE"

    config.add_view(forbidden_view,
                    renderer="json",
                    context="pyramid.exceptions.Forbidden")


def testincludeme2(config):
    """Config include that sets up a TestAuthnPolicy2."""
    config.set_authentication_policy(TestAuthnPolicy2())


def testincludemenull(config):
    """Config include that doesn't do anything."""
    pass


def testincludeme3(config):
    """Config include that adds a TestAuthPolicy3 and commits it."""
    config.set_authentication_policy(TestAuthnPolicy3())
    config.commit()


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
        policy = SelectableAuthenticationPolicy(policies)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)

        self.assertEquals(policy.authenticated_userid(self.request),
                          "test1")
        self.assertEquals(sorted(policy.effective_principals(self.request)),
                          [Authenticated, Everyone, "test1"])

    def test_policy_selected_event(self):

        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = SelectableAuthenticationPolicy(policies)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)

        self.assertEquals(policy.authenticated_userid(self.request), "test2")

    def test_selected_policy_cached(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = SelectableAuthenticationPolicy(policies)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)

        self.assertEquals(policy.unauthenticated_userid(self.request), "test2")
        policies.reverse()
        self.assertEquals(policy.unauthenticated_userid(self.request), "test2")

    def test_stacking_of_authenticated_userid(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = SelectableAuthenticationPolicy(policies)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)

        self.assertEquals(policy.authenticated_userid(self.request), "test2")
        policies.reverse()
        self.assertEquals(policy.authenticated_userid(self.request), "test2")

    def test_stacking_of_effective_principals(self):
        policies = [TestAuthnPolicy3(), TestAuthnPolicy2()]
        policy = SelectableAuthenticationPolicy(policies)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)

        self.assertEquals(sorted(policy.effective_principals(self.request)),
                          [Authenticated, Everyone, "test3", "test4"])
        policies.reverse()
        self.assertEquals(sorted(policy.effective_principals(self.request)),
                          [Authenticated, Everyone, "test3", "test4"])
        policies.append(TestAuthnPolicy1())
        self.assertEquals(sorted(policy.effective_principals(self.request)),
                          [Authenticated, Everyone, "test3", "test4"])

    def test_stacking_of_remember_and_forget(self):
        policies = [TestAuthnPolicy1(), TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = SelectableAuthenticationPolicy(policies)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)

        self.assertEquals(policy.remember(self.request, "ha"),
                          [("X-Remember", "ha")])
        self.assertEquals(policy.forget(self.request),
                          [("X-Forget", "foo")])
        policies.reverse()
        self.assertEquals(policy.remember(self.request, "ha"),
                          [("X-Remember", "ha")])
        self.assertEquals(policy.forget(self.request),
                          [("X-Forget", "foo")])

    def test_includeme_uses_acl_authorization_by_default(self):
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthorizationPolicy)
        expected = pyramid.authorization.ACLAuthorizationPolicy
        self.assertTrue(isinstance(policy, expected))

    def test_includeme_reads_authorization_from_settings(self):
        self.config.add_settings({
            "selectauth.authorization_policy": "pyramid_selectauth.tests."
            "TestAuthzPolicyCustom"
        })
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthorizationPolicy)
        self.assertTrue(isinstance(policy, TestAuthzPolicyCustom))

    def test_includeme_by_module(self):
        self.config.add_settings({
            "selectauth.policies": "pyramid_selectauth.tests.testincludeme1 "
                                   "pyramid_selectauth.tests.testincludeme2 "
                                   "pyramid_selectauth.tests.testincludemenull"
                                   " pyramid_selectauth.tests.testincludeme3"
        })
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertEquals(len(policy._policies), 3)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)
        # Check that they stack correctly.
        self.assertEquals(policy.unauthenticated_userid(self.request), "test1")
        self.assertEquals(policy.authenticated_userid(self.request), "test1")
        # Check that the forbidden view gets invoked.
        self.config.add_route("index", path="/")
        self.config.add_view(raiseforbidden, route_name="index")
        app = self.config.make_wsgi_app()
        environ = {"PATH_INFO": "/", "REQUEST_METHOD": "GET"}

        def start_response(*args):
            pass

        result = b"".join(app(environ, start_response))
        self.assertEquals(result, b'"FORBIDDEN ONE"')

    def test_includeme_by_callable(self):
        self.config.add_settings({
            "selectauth.policies":
                "pyramid_selectauth.tests.testincludeme1 policy1 policy2",
            "selectauth.policy.policy1.use":
                "pyramid_selectauth.tests.TestAuthnPolicy2",
            "selectauth.policy.policy1.foo":
                "bar",
            "selectauth.policy.policy2.use":
                "pyramid_selectauth.tests.TestAuthnPolicy3"
        })
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)
        self.assertEquals(len(policy._policies), 3)
        self.assertEquals(policy._policies[1].foo, "bar")
        # Check that they stack correctly.
        self.assertEquals(policy.unauthenticated_userid(self.request), "test1")
        self.assertEquals(policy.authenticated_userid(self.request), "test1")
        # Check that the forbidden view gets invoked.
        self.config.add_route("index", path="/")
        self.config.add_view(raiseforbidden, route_name="index")
        app = self.config.make_wsgi_app()
        environ = {"PATH_INFO": "/", "REQUEST_METHOD": "GET"}

        def start_response(*args):
            pass

        result = b"".join(app(environ, start_response))
        self.assertEquals(result, b'"FORBIDDEN ONE"')

    def test_includeme_with_unconfigured_policy(self):
        self.config.add_settings({
            "selectauth.policies":
                "pyramid_selectauth.tests.testincludeme1 policy1 policy2",
            "selectauth.policy.policy1.use":
                "pyramid_selectauth.tests.TestAuthnPolicy2",
            "selectauth.policy.policy1.foo":
                "bar",
        })
        self.assertRaises(ValueError, self.config.include,
                          "pyramid_selectauth")

    def test_get_policies(self):
        self.config.add_settings({
            "selectauth.policies":
                "pyramid_selectauth.tests.testincludeme1 policy1 policy2",
            "selectauth.policy.policy1.use":
                "pyramid_selectauth.tests.TestAuthnPolicy2",
            "selectauth.policy.policy2.use":
                "pyramid_selectauth.tests.TestAuthnPolicy3"
        })
        self.config.include("pyramid_selectauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        policies = policy.get_policies()
        expected_result = [TestAuthnPolicy1, TestAuthnPolicy2,
                           TestAuthnPolicy3]
        for (obtained, expected) in zip(policies, expected_result):
            self.assertEquals(obtained, expected)

    def test_select_first_policy_with_unauthenticated_userid(self):
        policies = [TestAuthnPolicyNull(), TestAuthnPolicy3()]
        policy = SelectableAuthenticationPolicy(policies)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)

        self.assertEquals(sorted(policy.effective_principals(self.request)),
                          [Authenticated, Everyone, "test3", "test4"])

    def test_no_good_policy(self):
        policies = [TestAuthnPolicyNull(), TestAuthnPolicyUnauthOnly()]
        policy = SelectableAuthenticationPolicy(policies)
        self.request.set_property(policy.select_policy,
                                  'selected_policy', reify=True)

        self.assertEquals(sorted(policy.effective_principals(self.request)),
                          [Everyone])
