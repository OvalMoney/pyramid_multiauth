# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Pyramid authn policy that ties together multiple backends.
"""

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy, PHASE2_CONFIG
from pyramid.security import Everyone, Authenticated

__ver_major__ = 0
__ver_minor__ = 0
__ver_patch__ = 2
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


@implementer(IAuthenticationPolicy)
class SelectableAuthenticationPolicy(object):
    """
    """
    def __init__(self, policies):
        self._policies = policies

    def select_policy(self, request):
        for policy in self._policies:
            if policy.unauthenticated_userid(request):
                return policy

    def authenticated_userid(self, request):
        """
        """
        policy = request.selected_policy
        if policy:
            return policy.authenticated_userid(request)

    def unauthenticated_userid(self, request):
        """
        """
        policy = request.selected_policy
        if policy:
            return policy.unauthenticated_userid(request)

    def effective_principals(self, request):
        """
        """
        principals = {Everyone}
        policy = request.selected_policy
        if policy:
            userid = policy.authenticated_userid(request)
            if userid:
                principals.update(policy.effective_principals(request))
                principals.add(Authenticated)
                principals.add(userid)
        return list(principals)

    def remember(self, request, principal, **kw):
        """
        """
        headers = []
        policy = request.selected_policy
        if policy:
            headers.extend(policy.remember(request, principal, **kw))
        return headers

    def forget(self, request):
        """
        """
        headers = []
        policy = request.selected_policy
        if policy:
            headers.extend(policy.forget(request))
        return headers

    def get_policies(self):
        """
        """
        return [p.__class__ for p in self._policies]


def includeme(config):
    """
    """
    # Grab the pyramid-wide settings, to look for any auth config.
    settings = config.get_settings()
    # Hook up a default AuthorizationPolicy.
    # Get the authorization policy from config if present.
    # Default ACLAuthorizationPolicy is usually what you want.
    authz_class = settings.get("selectauth.authorization_policy",
                               "pyramid.authorization.ACLAuthorizationPolicy")
    authz_policy = config.maybe_dotted(authz_class)()
    # If the app configures one explicitly then this will get overridden.
    # In autocommit mode this needs to be done before setting the authn policy.
    config.set_authorization_policy(authz_policy)
    # Look for callable policy definitions.
    # Suck them all out at once and store them in a dict for later use.
    policy_definitions = get_policy_definitions(settings)
    # Read and process the list of policies to load.
    # We build up a list of callables which can be executed at config commit
    # time to obtain the final list of policies.
    # Yeah, it's complicated.  But we want to be able to inherit any default
    # views or other config added by the sub-policies when they're included.
    # Process policies in reverse order so that things at the front of the
    # list can override things at the back of the list.
    policy_factories = []
    policy_names = settings.get("selectauth.policies", "").split()
    for policy_name in reversed(policy_names):
        if policy_name in policy_definitions:
            # It's a policy defined using a callable.
            # Just append it straight to the list.
            definition = policy_definitions[policy_name]
            factory = config.maybe_dotted(definition.pop("use"))
            policy_factories.append((factory, policy_name, definition))
        else:
            # It's a module to be directly included.
            try:
                factory = policy_factory_from_module(config, policy_name)
            except ImportError:
                err = "pyramid_selectauth: policy %r has no settings "\
                      "and is not importable" % (policy_name,)
                raise ValueError(err)
            policy_factories.append((factory, policy_name, {}))
    # OK.  We now have a list of callbacks which need to be called at
    # commit time, and will return the policies in reverse order.
    # Register a special action to pull them into our list of policies.
    policies = []

    def grab_policies():
        for factory, name, kwds in policy_factories:
            policy = factory(**kwds)
            if policy:
                policies.insert(0, policy)

    config.action(None, grab_policies, order=PHASE2_CONFIG)
    authn_policy = SelectableAuthenticationPolicy(policies)
    config.add_request_method(authn_policy.select_policy,
                              'selected_policy', reify=True)
    config.set_authentication_policy(authn_policy)


def policy_factory_from_module(config, module):
    """Create a policy factory that works by config.include()'ing a module.

    This function does some trickery with the Pyramid config system. Loosely,
    it does config.include(module), and then sucks out information about the
    authn policy that was registered.  It's complicated by pyramid's delayed-
    commit system, which means we have to do the work via callbacks.
    """
    # Remember the policy that's active before including the module, if any.
    orig_policy = config.registry.queryUtility(IAuthenticationPolicy)
    # Include the module, so we get any default views etc.
    config.include(module)
    # That might have registered and commited a new policy object.
    policy = config.registry.queryUtility(IAuthenticationPolicy)
    if policy is not None and policy is not orig_policy:
        return lambda: policy
    # Or it might have set up a pending action to register one later.
    # Find the most recent IAuthenticationPolicy action, and grab
    # out the registering function so we can call it ourselves.
    for action in reversed(config.action_state.actions):
        # Extract the discriminator and callable.  This is complicated by
        # Pyramid 1.3 changing action from a tuple to a dict.
        try:
            discriminator = action["discriminator"]
            callable = action["callable"]
        except TypeError:              # pragma: nocover
            discriminator = action[0]  # pragma: nocover
            callable = action[1]       # pragma: nocover
        # If it's not setting the authn policy, keep looking.
        if discriminator is not IAuthenticationPolicy:
            continue

        # Otherwise, wrap it up so we can extract the registered object.
        def grab_policy(register=callable):
            old_policy = config.registry.queryUtility(IAuthenticationPolicy)
            register()
            new_policy = config.registry.queryUtility(IAuthenticationPolicy)
            config.registry.registerUtility(old_policy, IAuthenticationPolicy)
            return new_policy

        return grab_policy
    # Or it might not have done *anything*.
    # So return a null policy factory.
    return lambda: None


def get_policy_definitions(settings):
    """Find all selectauth policy definitions from the settings dict.

    This function processes the paster deployment settings looking for items
    that start with "selectauth.policy.<policyname>.".  It pulls them all out
    into a dict indexed by the policy name.
    """
    policy_definitions = {}
    for name in settings:
        if not name.startswith("selectauth.policy."):
            continue
        value = settings[name]
        name = name[len("selectauth.policy."):]
        policy_name, setting_name = name.split(".", 1)
        if policy_name not in policy_definitions:
            policy_definitions[policy_name] = {}
        policy_definitions[policy_name][setting_name] = value
    return policy_definitions
