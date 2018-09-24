# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Pyramid authn policy that ties together multiple backends.
"""
import operator
import functools

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
        """Appends a new policy to the list of policies
        """
        factory_or_policy = config.maybe_dotted(policy)
        if callable(factory_or_policy):
            self._policies.append(factory_or_policy(config))
        else:
            self._policies.append(factory_or_policy)

    def proxy_method(method):
        """Decorator that automagically fetches the result of the
        selected policy method and passes it through to the selectauth policy
        to be returned"""
        @functools.wraps(method)
        def _proxied(self, request, *args, **kw):
            policy = self.select_policy_property(request)
            proxied_result = None
            if policy:
                proxied_method = getattr(policy, method.__name__)
                proxied_result = proxied_method(request, *args, **kw)
            return method(self, request, proxied_result, *args, **kw)
        return _proxied

    @proxy_method
    def authenticated_userid(self, request, proxied_result):
        """Returns the `authenticated_userid` result from the selected policy
        """
        return proxied_result

    @proxy_method
    def unauthenticated_userid(self, request, proxied_result):
        """Returns the `unauthenticated_userid` result from the selected policy
        """
        return proxied_result

    @proxy_method
    def effective_principals(self, request, proxied_result):
        """Returns the `effective_principals` result from the selected policy
        """
        principals = {Everyone}
        principals.update(
            proxied_result or set()
        )
        return list(principals)

    @proxy_method
    def remember(self, request, proxied_result, principal, **kw):
        """Returns the `remember` result from the selected policy
        """
        return proxied_result or []

    @proxy_method
    def forget(self, request, proxied_result):
        """Returns the `forget` result from the selected policy
        """
        return proxied_result or []

    def get_policies(self):
        """Returns the registered policies classes (not the instances)
        """
        return [p.__class__ for p in self._policies]
