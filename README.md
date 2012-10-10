# Active Directory Authorization for Orchard

[Orchard](http://www.orchardproject.net/) is a community driven content management system that allows users to rapidly create websites for the .NET platform. This module overrides the default authentication & authorization by using the currently logged in active directory user instead of requiring a user to authenticate using credentials.

## How it works

This [blog post](http://peterkeating.co.uk/active-directory-authorization-module-for-orchard/) contains more detail about why we built the module and how it works.

## Status

Module has been released and is now [available from the Orchard Gallery](https://gallery.orchardproject.net/List/Modules/Orchard.Module.ActiveDirectoryAuthorization/1.0).

## Installation

In order to install the module follow the steps below.

* Add any roles that your active directory users have that aren't currently in your Orchard instance. It is important that the name of the Orchard role matches the name of the role in your active directory.

* In the modules section in the administration dashboard for your Orchard install search the gallery for "Active Directory Authorization" and then Download the module titled "Active Directory Authorization". Ensure that you have completed the first step of adding the roles before you enable the module otherwise you may lock yourself out of the administration dashboard.

* Once the module is installed and enabled, you need to setup IIS to enable windows authentication.
	To do this you should open IIS and navigate to your website. Select the "Authentication" option, then enable "Windows Authentication", and have the rest as disabled.

* The final step is to change the authentication configuration in the Web.config of the root of your website, replacing the current configuration to use FormsAuthentication.
	<pre><code>&lt;authentication mode="Windows" /&gt;
	&lt;roleManager enabled="true" defaultProvider="AspNetWindowsTokenRoleProvider"/&gt;
	</code></pre>


