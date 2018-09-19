==================
pyramid_selectauth
==================

|pypi| |travis|

.. |pypi| image:: https://img.shields.io/pypi/v/pyramid_selectauth.svg
    :target: https://pypi.python.org/pypi/pyramid_selectauth

.. |travis| image:: https://travis-ci.org/mozilla-services/pyramid_selectauth.svg?branch=master
    :target: https://travis-ci.org/mozilla-services/pyramid_selectauth


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
    authn_policy = SelectableAuthenticationPolicy(policies)
    config.add_request_method('selected_policy', authn_policy.select_policy, reify=True)
    config.set_authentication_policy(authn_policy)

This example uses the pyramid_ipauth module to assign effective principals
based on originating IP address of the request.  It combines two such
policies so that requests originating from "127.0.*.*" will have principal
"local" while requests originating from "192.168.*.*" will have principal
"trusted".

The default selection function will call *unauthenticated_userid* on the provided
policies in order, and select the first one that does not return `None`.


Deployment Settings
===================

It is also possible to specify the authentication policies as part of your
paste deployment settings.  Consider the following example::

    [app:pyramidapp]
    use = egg:mypyramidapp

    selectauth.policies = ipauth1 ipauth2 pyramid_browserid

    selectauth.policy.ipauth1.use = pyramid_ipauth.IPAuthentictionPolicy
    selectauth.policy.ipauth1.ipaddrs = 127.0.*.*
    selectauth.policy.ipauth1.principals = local

    selectauth.policy.ipauth2.use = pyramid_ipauth.IPAuthentictionPolicy
    selectauth.policy.ipauth2.ipaddrs = 192.168.*.*
    selectauth.policy.ipauth2.principals = trusted

To configure authentication from these settings, simply include the multiauth
module into your configurator::

    config.include("pyramid_selectauth")

In this example you would get a SelectableAuthenticationPolicy with three stacked
auth policies.  The first two, ipauth1 and ipauth2, are defined as the name of
of a callable along with a set of keyword arguments.  The third is defined as
the name of a module, pyramid_browserid, which will be procecesed via the
standard config.include() mechanism.

The end result would be a system that authenticates users via BrowserID, and
assigns additional principal identifiers based on the originating IP address
of the request.

If necessary, the *group finder function* and the *authorization policy* can
also be specified from configuration::

    [app:pyramidapp]
    use = egg:mypyramidapp

    selectauth.authorization_policy = mypyramidapp.acl.Custom

    ...
