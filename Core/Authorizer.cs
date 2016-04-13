using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Security;
using ActiveDirectoryAuthorization.Models;
using Orchard.ContentManagement;
using Orchard.Environment.Extensions;
using Orchard.Localization;
using Orchard.Security;
using Orchard.Security.Permissions;
using Orchard.UI.Notify;
using Orchard.Users.Models;
using System.DirectoryServices.AccountManagement;
using Orchard.Roles.Services;
using System.Collections.Generic;
using Orchard.Roles.Models;
using Orchard.Data;

namespace ActiveDirectoryAuthorization.Core
{
    [OrchardSuppressDependency("Orchard.Security.Authorizer")]
    public class Authorizer : IAuthorizer
    {
        private const int Hashed = 1;

        private readonly IAuthorizationService _authorizationService;
        private readonly INotifier _notifier;
        private readonly IContentManager _contentManager;
        private readonly IRoleService _roleService;
        private readonly IRepository<UserRolesPartRecord> _userRolesRepository;

        public Authorizer(IAuthorizationService authorizationService, INotifier notifier, IContentManager contentManager, IRoleService roleService, IRepository<UserRolesPartRecord> userRolesRepository)
        {
            _authorizationService = authorizationService;
            _notifier = notifier;
            _contentManager = contentManager;
            _roleService = roleService;
            _userRolesRepository = userRolesRepository;

            T = NullLocalizer.Instance;
        }

        public Localizer T { get; set; }

        public bool Authorize(Permission permission)
        {
            return Authorize(permission, null, null);
        }

        public bool Authorize(Permission permission, LocalizedString message)
        {
            return Authorize(permission, null, message);
        }

        public bool Authorize(Permission permission, IContent content)
        {
            return Authorize(permission, content, null);
        }

        public bool Authorize(Permission permission, IContent content, LocalizedString message)
        {
            // creates a user for the active directory user if one doesn't already
            // exist. If one does already exists then that user from the database
            // is returned by the method.
            var user = CreateUserForActiveDirectoryUserIfNotExists(new ActiveDirectoryUser());

            // attempts to authorize the active directory user based on their roles
            // and the permissions that their associated roles have.
            if (_authorizationService.TryCheckAccess(permission, user, content))
                return true;

            if (message != null) {
                _notifier.Error(T("{0}. Current user, {2}, does not have {1} permission.",
                                    message, permission.Name, user.UserName));
            }

            return false;
        }

        /// <summary>
        /// Loops through the active directory user roles, if the role is an
        /// orchard role then the user is assigned to that role.
        /// </summary>
        /// <param name="user">Orchard User who will have the roles set for them.</param>
        /// <param name="activeDirectoryRoles">Currently logged in active directory user roles.</param>
        private void CreateUserRoles(IUser user, IList<string> activeDirectoryRoles)
        {
            var availableRoles = _roleService.GetRoles();

            // loops through the active directory roles trying to match to an
            // orchard role, if one is found then the user is assigned to that
            // role.
            foreach (var activeDirectoryRole in activeDirectoryRoles)
            {
                var orchardRole = availableRoles.Where(x => x.Name.ToLower() == activeDirectoryRole.ToLower()).SingleOrDefault();

                if (orchardRole != null)
                    _userRolesRepository.Create(new UserRolesPartRecord { Role = orchardRole, UserId = user.Id });
            }
        }

        /// <summary>
        /// Does a check to see if there is an Orchard user that represents the active directory user.
        /// If there isn't then one is created with the username from the active directory user.
        /// </summary>
        /// <param name="activeDirectoryUser">Currently logged in active directory user.</param>
        /// <returns>Returns the user that was created, or if one wasn't created then the
        /// UserPart that is already in the database is returned.</returns>
        private IUser CreateUserForActiveDirectoryUserIfNotExists(ActiveDirectoryUser activeDirectoryUser)
        {
            var user = GetUser(activeDirectoryUser.UserName);

            if (user == null && !String.IsNullOrEmpty(activeDirectoryUser.UserName))
            {
                user = CreateUser(new CreateUserParams(activeDirectoryUser.UserName, "password", GetEmail(activeDirectoryUser), String.Empty, String.Empty, true));
                CreateUserRoles(user, activeDirectoryUser.Roles);
            }

            return user;
        }

        /// <summary>
        /// Creates a UserPart that will be tied to the active directory
        /// username to allow the user to use the core Orchard functionality.
        /// </summary>
        /// <param name="createUserParams"></param>
        /// <returns>The user object that was saved to the database.</returns>
        private IUser CreateUser(CreateUserParams createUserParams)
        {
            var user = _contentManager.New<UserPart>("User");

            user.Record.UserName = createUserParams.Username;
            user.Record.Email = createUserParams.Email;
            user.Record.NormalizedUserName = createUserParams.Username.ToLowerInvariant();
            user.Record.HashAlgorithm = "SHA1";
            user.Record.RegistrationStatus = UserStatus.Approved;
            user.Record.EmailStatus = UserStatus.Approved;
            SetPasswordHashed(user.Record, createUserParams.Password);

            _contentManager.Create(user);

            return user;
        }

        /// <summary>
        /// Makes an attempt to communicate with LDAP to retrieve the email
        /// of the active directory user.
        /// </summary>
        /// <param name="activeDiretoryUser">Currently logged in active directory user.</param>
        /// <returns>Email address of active directory user if connection can be
        /// made to LDAP, otherwise an empty string is returned.</returns>
        private string GetEmail(ActiveDirectoryUser activeDirectoryUser)
        {
            var domainAndUserName = activeDirectoryUser.UserName.Split('\\');
            var email = "";

            if (domainAndUserName.Length == 2)
            {
                try
                {
                    var ctx = new PrincipalContext(ContextType.Domain, domainAndUserName[0]);
                    var up = UserPrincipal.FindByIdentity(ctx, activeDirectoryUser.UserName);

                    if (up != null && up.EmailAddress != null)
                        email = up.EmailAddress.ToLowerInvariant();
                }
                catch { }
            }

            return email;
        }

        /// <summary>
        /// Attempts to get a UserPart that is associated to the
        /// active directory username from the content manager.
        /// </summary>
        /// <param name="username">Username of the active directory user.</param>
        /// <returns>UserPart if found, otherwise null.</returns>
        private IUser GetUser(string username)
        {
            var lowerName = username == null ? "" : username.ToLowerInvariant();
            return _contentManager.Query<UserPart, UserPartRecord>().Where(u => u.NormalizedUserName == lowerName).List().FirstOrDefault();
        }

        /// <summary>
        /// Sets a fake password on the User. This password will never be used as the users
        /// will automatically be logged in via active directory.
        /// </summary>
        /// <param name="partRecord"></param>
        /// <param name="password"></param>
        private static void SetPasswordHashed(UserPartRecord partRecord, string password)
        {
            var saltBytes = new byte[0x10];
            using (var random = new RNGCryptoServiceProvider())
            {
                random.GetBytes(saltBytes);
            }

            var passwordBytes = Encoding.Unicode.GetBytes(password);

            var combinedBytes = saltBytes.Concat(passwordBytes).ToArray();

            byte[] hashBytes;
            using (var hashAlgorithm = HashAlgorithm.Create(partRecord.HashAlgorithm))
            {
                hashBytes = hashAlgorithm.ComputeHash(combinedBytes);
            }

            partRecord.PasswordFormat = MembershipPasswordFormat.Hashed;
            partRecord.Password = Convert.ToBase64String(hashBytes);
            partRecord.PasswordSalt = Convert.ToBase64String(saltBytes);
        }
    }
}
