using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using Orchard.ContentManagement;
using Orchard.Roles.Models;
using Orchard.Security;

namespace ActiveDirectoryAuthorization.Models
{
    public class ActiveDirectoryUser : IUser, IUserRoles
    {
        private string _username;
        private IList<string> _roles;

        public string UserName
        {
            get { return _username; }
            set { _username = value; }
        }

        public string Email
        {
            get { return String.Empty; }
        }

        public ContentItem ContentItem
        {
            get { return null; }
        }

        public int Id
        {
            get { return -1; }
        }

        public IList<string> Roles
        {
            get { return _roles; }
        }

        public ActiveDirectoryUser()
        {
            // gets the username of the current active directory user.
            _username = HttpContext.Current.User.Identity.Name;

            // gets the current roles for the current user logged in for this context.
            try { _roles = System.Web.Security.Roles.GetRolesForUser(_username).ToList(); } catch { _roles = new List<string>(); }
        }
    }
}