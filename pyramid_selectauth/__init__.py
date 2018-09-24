from pyramid.exceptions import ConfigurationError
from pyramid.interfaces import IAuthenticationPolicy
from .policy import SelectableAuthenticationPolicy, ISelectableAuthPolicy

__all__ = ['SelectableAuthenticationPolicy',
           'ISelectableAuthPolicy',
           'create_selectable_authentication_policy',
           'set_selectable_authentication_policy']

__ver_major__ = 1
__ver_minor__ = 0
__ver_patch__ = 1
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__

DEFAULT_CLASS = SelectableAuthenticationPolicy


def includeme(config):
    settings = config.get_settings()
    auth_class = config.maybe_dotted(settings.get("selectauth.policy_class",
                                     SelectableAuthenticationPolicy))
    policy = create_selectable_authentication_policy(config, [], auth_class)
    policy_names = settings.get("selectauth.policies")
    if not isinstance(policy_names, list):
        if isinstance(policy_names, str):
            policy_names = policy_names.split()
        elif not policy_names:
            policy_names = []
        else:
            raise ConfigurationError("Invalid config: selectauth.policies")
    for policy_name in policy_names:
        subpolicy = config.maybe_dotted(policy_name)
        if callable(subpolicy):
            if IAuthenticationPolicy.implementedBy(subpolicy):
                subpolicy = subpolicy()
            else:
                subpolicy = subpolicy(config)
        policy.add_policy(config, subpolicy)
    config.set_authentication_policy(policy)


def create_selectable_authentication_policy(config, policies=None,
                                            _class=DEFAULT_CLASS):
    if not policies:
        policies = []
    if not ISelectableAuthPolicy.implementedBy(_class):
        raise ConfigurationError(
            "The selectauth policy class should extend "
            "pyramid_selectauth.SelectableAuthenticationPolicy")
    _policy = _class(policies)
    config.add_request_method(_policy.select_policy, 'sa_selected_policy',
                              reify=True)
    config.add_directive('add_selectauth_policy', _policy.add_policy)
    return _policy


def set_selectable_authentication_policy(config, policies=None,
                                         _class=DEFAULT_CLASS):
    if not policies:
        policies = []
    _policy = create_selectable_authentication_policy(config, policies, _class)
    config.set_authentication_policy(_policy)
