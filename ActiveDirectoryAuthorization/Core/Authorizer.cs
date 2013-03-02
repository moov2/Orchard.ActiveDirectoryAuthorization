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

namespace ActiveDirectoryAuthorization.Core
{
    [OrchardSuppressDependency("Orchard.Security.Authorizer")]
    public class Authorizer : IAuthorizer
    {
        private const int Hashed = 1;

        private readonly IAuthorizationService _authorizationService;
        private readonly INotifier _notifier;
        private readonly IContentManager _contentManager;

        public Authorizer(IAuthorizationService authorizationService, INotifier notifier, IContentManager contentManager)
        {
            _authorizationService = authorizationService;
            _notifier = notifier;
            _contentManager = contentManager;

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
            // gets the current active directory user.
            var user = new ActiveDirectoryUser();

            // attempts to authorize the active directory user based on their roles
            // and the permissions that their associated roles have.
            if (_authorizationService.TryCheckAccess(permission, user, content))
            {
                CreateUserForActiveDirectoryUserIfNotExists(user);
                return true;
            }

            if (message != null) {
                _notifier.Error(T("{0}. Current user, {2}, does not have {1} permission.",
                                    message, permission.Name, user.UserName));
            }

            return false;
        }

        /// <summary>
        /// Does a check to see if there is a UserPart for the active directory user. If there
        /// isn't then one is created with the username from the ActiveDirectoryUser.
        /// </summary>
        /// <param name="activeDirectoryUser">Currently logged in active directory user.</param>
        private void CreateUserForActiveDirectoryUserIfNotExists(IUser activeDirectoryUser)
        {
            var user = GetUser(activeDirectoryUser.UserName);

            if (user == null && !String.IsNullOrEmpty(activeDirectoryUser.UserName))
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
                    } catch { }
                }

                CreateUser(new CreateUserParams(activeDirectoryUser.UserName, "password", email, String.Empty, String.Empty, true));
            }
        }

        /// <summary>
        /// Creates a UserPart that will be tied to the active directory
        /// username to allow the user to use the core Orchard functionality.
        /// </summary>
        /// <param name="createUserParams"></param>
        private void CreateUser(CreateUserParams createUserParams)
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

            // Flush the session now so any calls to authentication service is able to pick up the new user.
            _contentManager.Flush();
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
