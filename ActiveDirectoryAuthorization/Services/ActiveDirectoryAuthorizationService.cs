using System;
using System.Collections.Generic;
using System.Linq;
using Orchard.Localization;
using Orchard.Logging;
using Orchard.ContentManagement;
using Orchard.Roles.Models;
using Orchard.Security;
using Orchard.Security.Permissions;
using ActiveDirectoryAuthorization.Models;
using Orchard.Roles.Services;
using Orchard;
using Orchard.Environment.Extensions;

namespace ActiveDirectoryAuthorization.Services
{
    [OrchardSuppressDependency("Orchard.Roles.Services.RolesBasedAuthorizationService")]
    public class ActiveDirectoryRolesBasedAuthorizationService : IAuthorizationService
    {
        private readonly IRoleService _roleService;
        private readonly IWorkContextAccessor _workContextAccessor;
        private readonly IAuthorizationServiceEventHandler _authorizationServiceEventHandler;
        private readonly IMembershipService _membershipService;

        private static readonly string[] AnonymousRole = new[] { "Anonymous" };
        private static readonly string[] AuthenticatedRole = new[] { "Authenticated" };

        public ActiveDirectoryRolesBasedAuthorizationService(IRoleService roleService, IWorkContextAccessor workContextAccessor, IAuthorizationServiceEventHandler authorizationServiceEventHandler)
        {
            _roleService = roleService;
            _workContextAccessor = workContextAccessor;
            _authorizationServiceEventHandler = authorizationServiceEventHandler;

            T = NullLocalizer.Instance;
            Logger = NullLogger.Instance;
        }

        public Localizer T { get; set; }
        public ILogger Logger { get; set; }


        public void CheckAccess(Permission permission, IUser user, IContent content)
        {
            if (!TryCheckAccess(permission, user, content))
            {
                throw new OrchardSecurityException(T("A security exception occurred in the content management system."))
                {
                    PermissionName = permission.Name,
                    User = user,
                    Content = content
                };
            }
        }

        public bool TryCheckAccess(Permission permission, IUser user, IContent content)
        {
            user = new ActiveDirectoryUser();

            var context = new CheckAccessContext { Permission = permission, User = user, Content = content };
            _authorizationServiceEventHandler.Checking(context);

            for (var adjustmentLimiter = 0; adjustmentLimiter != 3; ++adjustmentLimiter)
            {
                if (!context.Granted && context.User != null)
                {
                    if (!String.IsNullOrEmpty(_workContextAccessor.GetContext().CurrentSite.SuperUser) &&
                           String.Equals(context.User.UserName, _workContextAccessor.GetContext().CurrentSite.SuperUser, StringComparison.Ordinal))
                    {
                        context.Granted = true;
                    }
                }

                if (!context.Granted)
                {
                    // determine which set of permissions would satisfy the access check
                    var grantingNames = PermissionNames(context.Permission, Enumerable.Empty<string>()).Distinct().ToArray();

                    // determine what set of roles should be examined by the access check
                    IEnumerable<string> rolesToExamine;
                    if (context.User == null)
                    {
                        rolesToExamine = AnonymousRole;
                    }
                    else
                    {
                        // the current user is not null, so get his roles and add "Authenticated" to it.

                        // This line has been changed from the core implementation of IAuthorizationService,
                        // because our ActiveDirectoryUser implements the IUserRoles interface instead of having
                        // an UserRolesPart included on the content.
                        rolesToExamine = (context.User as IUserRoles).Roles;

                        // when it is a simulated anonymous user in the admin
                        if (!rolesToExamine.Contains(AnonymousRole[0]))
                        {
                            rolesToExamine = rolesToExamine.Concat(AuthenticatedRole);
                        }
                    }
   
                    foreach (var role in rolesToExamine)
                    {
                        foreach (var permissionName in _roleService.GetPermissionsForRoleByName(role))
                        {
                            string possessedName = permissionName;
                            if (grantingNames.Any(grantingName => String.Equals(possessedName, grantingName, StringComparison.OrdinalIgnoreCase)))
                            {
                                context.Granted = true;
                            }

                            if (context.Granted)
                                break;
                        }

                        if (context.Granted)
                            break;
                    }
                }

                context.Adjusted = false;
                _authorizationServiceEventHandler.Adjust(context);
                if (!context.Adjusted)
                    break;
            }

            _authorizationServiceEventHandler.Complete(context);

            return context.Granted;
        }

        private static IEnumerable<string> PermissionNames(Permission permission, IEnumerable<string> stack)
        {
            // the given name is tested
            yield return permission.Name;

            // iterate implied permissions to grant, it present
            if (permission.ImpliedBy != null && permission.ImpliedBy.Any())
            {
                foreach (var impliedBy in permission.ImpliedBy)
                {
                    // avoid potential recursion
                    if (stack.Contains(impliedBy.Name))
                        continue;

                    // otherwise accumulate the implied permission names recursively
                    foreach (var impliedName in PermissionNames(impliedBy, stack.Concat(new[] { permission.Name })))
                    {
                        yield return impliedName;
                    }
                }
            }

            yield return StandardPermissions.SiteOwner.Name;
        }

    }
}
