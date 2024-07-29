using Novell.Directory.Ldap;
using System;

namespace LdapAuthentication
{
	public class LdapAuthenticationService
	{
		private readonly string _ldapServer = "your ad server";
		private readonly int _ldapPort = 389 (your port);
		private readonly string _baseDn = "DC=(domain name),DC=com";
		public (bool, string) Authenticate(string username, string password)
		{
			using var connection = new LdapConnection();
			try
			{
				string usernameWithDomain = username + "@example.com";
				connection.Connect(_ldapServer, _ldapPort);

				// Attempt to bind with the user's DN and password
				connection.Bind(usernameWithDomain, password);

				// Construct the search filter of your liking
				string searchFilter = $"(mail={usernameWithDomain})";

				// Perform an LDAP search to find the user's DN
				string userDn = FindUserDn(connection, _baseDn, searchFilter);

				if (userDn != null)
				{
					// Extract the CN value from the user's DN
					string cn = GetCommonName(userDn);
					return (connection.Bound, cn);
				}

				return (false, null);
			}
			catch (LdapException)
			{
				return (false, null);
			}
		}

		private static string GetCommonName(string userDn)
		{
			if (userDn != null)
			{
				var dnComponents = userDn.Split(',');
				foreach (var component in dnComponents)
				{
					if (component.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
					{
						return component[3..];
					}
				}
			}

			return string.Empty;
		}

		private static string FindUserDn(LdapConnection connection, string baseDn, string searchFilter)
		{
			try
			{
				LdapSearchConstraints searchConstraints = new()
				{
					ReferralFollowing = true
				};

				ILdapSearchResults searchResults = connection.Search(
					baseDn,
					LdapConnection.ScopeSub,
					searchFilter,
					null,
					false,
					searchConstraints
				);

				if (searchResults.HasMore())
				{
					var entry = searchResults.Next();
					return entry.Dn;
				}
			}
			finally
			{
				// No need to call Dispose for ILdapSearchResults
			}

			return null;
		}
	}
}