# Active Directory Authorization for Orchard

[Orchard](http://www.orchardproject.net/) is a community driven content management system that allows users to rapidly create websites for the .NET platform.

## Installation

In order to install the module follow the steps below.

* Add any roles that your active directory users have that aren't currently in your Orchard instance. It is important that the name of the Orchard role matches the name of the role in your active directory.

* Download the latest .nupkg from the downloads section of this repository.

* Install the module into your instance of Orchard follow the instructions for (installing a module from your local computer)[https://github.com/OrchardCMS/OrchardDoc/blob/master/Documentation/Installing-and-upgrading-modules.markdown#installing-a-module-from-your-local-computer]

* Once the module is installed and enabled, you need to setup IIS to enable windows authentication.
	To do this you should open IIS and navigate to your website. Select the "Authentication" option, then enable "Windows Authentication", and have the rest as disabled.

* The final step is to change the authentication configuration in the Web.config of the root of your website, replacing the current configuration to use FormsAuthentication.
	<pre><code>&lt;authentication mode="Windows" /&gt;
	&lt;roleManager enabled="true" defaultProvider="AspNetWindowsTokenRoleProvider"/&gt;
	</code></pre>


