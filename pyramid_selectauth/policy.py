# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Pyramid authn policy that ties together multiple backends.
"""
import operator

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone


@implementer(IAuthenticationPolicy)
class SelectableAuthenticationPolicy(object):
    """
    """
    def __init__(self, policies):
        self._policies = policies
        self._select_policy_property = None

    def select_policy(self, request):
        """Efficiently retrieves the first policy which property
        'unauthenticated_userid' returns not None, or returns None if
        no one does.
        """
        return next(filter(
            operator.methodcaller('unauthenticated_userid', request),
            self._policies), None)

    def select_policy_property(self, request):
        if self._select_policy_property:
            return self._select_policy_property
        if hasattr(request, 'sa_selected_policy'):
            self._select_policy_property = request.sa_selected_policy
        return self.select_policy(request)

    def add_policy(self, config, policy):
        factory_or_policy = config.maybe_dotted(policy)
        if callable(factory_or_policy):
            self._policies.append(factory_or_policy(config))
        else:
            self._policies.append(factory_or_policy)

    def authenticated_userid(self, request):
        """
        """
        policy = self.select_policy_property(request)
        if policy:
            return policy.authenticated_userid(request)

    def unauthenticated_userid(self, request):
        """
        """
        policy = self.select_policy_property(request)
        if policy:
            return policy.unauthenticated_userid(request)

    def effective_principals(self, request):
        """
        """
        principals = {Everyone}
        policy = self.select_policy_property(request)
        if policy:
            userid = policy.authenticated_userid(request)
            if userid:
                principals.update(policy.effective_principals(request))
        return list(principals)

    def remember(self, request, principal, **kw):
        """
        """
        headers = []
        policy = self.select_policy_property(request)
        if policy:
            headers.extend(policy.remember(request, principal, **kw))
        return headers

    def forget(self, request):
        """
        """
        headers = []
        policy = self.select_policy_property(request)
        if policy:
            headers.extend(policy.forget(request))
        return headers

    def get_policies(self):
        """
        """
        return [p.__class__ for p in self._policies]
