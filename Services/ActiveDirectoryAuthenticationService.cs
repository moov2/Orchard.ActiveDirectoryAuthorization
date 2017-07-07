using System.Web;
using ActiveDirectoryAuthorization.Models;
using Orchard.Environment.Extensions;
using Orchard.Security;
using Orchard.Environment;

namespace ActiveDirectoryAuthorization.Services
{
    [OrchardSuppressDependency("Orchard.Security.Providers.FormsAuthenticationService")]
    public class ActiveDirectoryAuthenticationService : IAuthenticationService
    {
        private readonly Work<IMembershipService> _membershipService;
        private IUser _authenticatedUser;

        public ActiveDirectoryAuthenticationService(Work<IMembershipService> membershipService)
        {
            _membershipService = membershipService;
        }

        public void SignIn(IUser user, bool createPersistentCookie)
        {
            // users are already signed in.
        }

        public void SignOut()
        {
           // users aren't able to sign out because they're automatically logged in.
        }

        public void SetAuthenticatedUserForRequest(IUser user)
        {
           // users are automatically authenticated via active directory.
        }

        /// <summary>
        /// Overrides the default behaviour to return an instance of ActiveDirectoryUser
        /// based on the current user in the context if a UserPart hasn't been created for
        /// the active directory user yet.
        /// </summary>
        /// <returns></returns>
        public IUser GetAuthenticatedUser()
        {
            if (HttpContext.Current == null || HttpContext.Current.User == null || !HttpContext.Current.User.Identity.IsAuthenticated)
                return null;
            
            // attempts to get the user from the UserPart data store if it wasn't previously set.
            if (_authenticatedUser == null)
                _authenticatedUser = _membershipService.Value.GetUser(HttpContext.Current.User.Identity.Name);

            // if the user wasn't previously set, and doesn't exist in the UserPart data store, then the
            // current active directory user is returned instead.
            if (_authenticatedUser == null)
                return new ActiveDirectoryUser();
            // return previously set user, or the user fetched from the data store.
            return _authenticatedUser;
        }
    }
}
