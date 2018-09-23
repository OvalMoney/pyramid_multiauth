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


class ISelectableAuthPolicy(IAuthenticationPolicy):
    def select_policy(request):
        """Method that should select the correct policy
        to use based on the current request
        """


@implementer(ISelectableAuthPolicy)
class SelectableAuthenticationPolicy(object):
    """Default selectable authentication policy that selects
    the authentication policy to use for the current request
    based on the 'unauthenticated_userid' method of the subpolicies.
    """
    def __init__(self, policies):
        self._policies = policies

    def select_policy(self, request):
        """Efficiently retrieves the first policy which method
        'unauthenticated_userid' returns not None, or returns None if
        no one does. Iterates through the policies in the order they are
        provided in the class initializer.
        """
        return next(filter(
            operator.methodcaller('unauthenticated_userid', request),
            self._policies), None)

    def select_policy_property(self, request):
        """Helper that uses the registered 'sa_selected_policy' property
        of the request or backs down on the policy's 'select_policy' method
        in case the property wasn't registered on the request.
        The registration of the 'sa_selected_policy' property is done when
        using the 'create_selectable_authentication_policy' or the
        'set_selectable_authentication_policy' factories.
        """
        if hasattr(request, 'sa_selected_policy'):
            return request.sa_selected_policy
        return self.select_policy(request)

    def add_policy(self, config, policy):
        factory_or_policy = config.maybe_dotted(policy)
        if callable(factory_or_policy):
            self._policies.append(factory_or_policy(config))
        else:
            self._policies.append(factory_or_policy)

    def _proxy_method(self, name, request, *args, **kw):
        policy = self.select_policy_property(request)
        if policy:
            return getattr(policy, name)(request, *args, **kw)

    def authenticated_userid(self, request):
        """Returns the `authenticated_userid` result from the selected policy
        """
        return self._proxy_method('authenticated_userid', request)

    def unauthenticated_userid(self, request):
        """Returns the `unauthenticated_userid` result from the selected policy
        """
        return self._proxy_method('unauthenticated_userid', request)

    def effective_principals(self, request):
        """Returns the `effective_principals` result from the selected policy
        """
        principals = {Everyone}
        principals.update(self._proxy_method('effective_principals', request) or set())
        return list(principals)

    def remember(self, request, principal, **kw):
        """Returns the `remember` result from the selected policy
        """
        return self._proxy_method('remember', request, principal, **kw) or []

    def forget(self, request):
        """Returns the `forget` result from the selected policy
        """
        return self._proxy_method('forget', request) or []

    def get_policies(self):
        """Returns the registered policies classes (not the instances)
        """
        return [p.__class__ for p in self._policies]
