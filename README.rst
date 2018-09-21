==================
pyramid_selectauth
==================

|pypi| |travis|

.. |pypi| image:: https://img.shields.io/pypi/v/pyramid_selectauth.svg
    :target: https://pypi.python.org/pypi/pyramid_selectauth

.. |travis| image:: https://travis-ci.org/OvalMoney/pyramid_selectauth.svg?branch=master
    :target: https://travis-ci.org/OvalMoney/pyramid_selectauth


An authentication policy for Pyramid that automagically selects the
correct policy to use for a specific request, given a list of authentication policies


Overview
========

SelectableAuthenticationPolicy is a Pyramid authentication policy that selects
*another* provided IAuthenticationPolicy object, to provide a different auth policy
based on the specific request.  Simply pass it a list of policies that
should be tried in order, and register the 'selected_policy' request method that
will select and cache the correct policy to use::

    policies = [
        IPAuthenticationPolicy("127.0.*.*", principals=["local"])
        IPAuthenticationPolicy("192.168.*.*", principals=["trusted"])
    ]
    set_selectable_authentication_policy(config, policies)

This example uses the pyramid_ipauth module to assign effective principals
based on originating IP address of the request.  It combines two such
policies so that requests originating from "127.0.*.*" will have principal
"local" while requests originating from "192.168.*.*" will have principal
"trusted".

You can use the *create_selectable_authentication_policy* factory to just create the
*SelectableAuthenticationPolicy* instance without setting it::

    policies = [
        IPAuthenticationPolicy("127.0.*.*", principals=["local"])
        IPAuthenticationPolicy("192.168.*.*", principals=["trusted"])
    ]
    policy = create_selectable_authentication_policy(config, policies)
    policy.add_policy(IPAuthenticationPolicy("10.0.*.*", principals=["not-so-trusted"]))
    config.set_authentication_policy(policy)

You can also just use *config.include()* to include the policy, and then add the subpolicies
with the registered *add_selectauth_policy* directive on config::

    config.include('pyramid_selectauth')
    config.add_selectauth_policy(IPAuthenticationPolicy("127.0.*.*", principals=["local"]))
    config.add_selectauth_policy(IPAuthenticationPolicy("192.168.*.*", principals=["trusted"]))

Policy selection method
=========================

The default selection method will call *unauthenticated_userid* on the provided
policies in order, and select the first one that does not return `None`.

You can change the selection method by extending the *SelectableAuthenticationPolicy* and
overriding the *select_policy* method with your logic to select the correct policy for the
current request, and then specifying your class in the factories::

    class MyPolicy(SelectableAuthenticationPolicy):
        def select_policy(self, request):
            return self._policies[0]  # Always uses the first policy (very useful!)


    policies = [
        IPAuthenticationPolicy("127.0.*.*", principals=["local"])
        IPAuthenticationPolicy("192.168.*.*", principals=["trusted"])
    ]
    policy = create_selectable_authentication_policy(config, policies, _class=MyPolicy)
    config.set_authentication_policy(policy)

Deployment Settings
===================

It is also possible to specify the authentication policies as part of your
paste deployment settings.  Consider the following example::

    [app:pyramidapp]
    use = egg:mypyramidapp

    selectauth.policy_class = mypyramidapp.policies.MySelectAuthPolicy
    selectauth.policies = mypyramidapp.policies.ipauthpolicyfactory mypyramidapp.policies.mypolicyfactory


To configure authentication from these settings, simply include the multiauth
module into your configurator::

    config.include("pyramid_selectauth")


