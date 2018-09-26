/*
 Description: This program authenticates a username and password against the iPlanet
 directory.  Authorization, determined by group membership, is also checked.

 Caveats:
 To use SSL communication, you need to instruct the program to trust certificates issued by
 the CA used to sign the LDAP server certificate.

 On a machine with keytool installed, run:
 	keytool -import -file CAPublicKeyFile.cer -keystore trustStoreFile
 Make sure whatever password you specify for your keystore is
 set as the trustStorePassword below

 History:
 	20080624	LJL		v1.0	Initial Code
 */

import javax.naming.*;
import javax.naming.directory.*;

import java.io.*;

import java.util.Hashtable;

import javax.net.ssl.*;

class TestJavaLDAPAuthSSL {

	public static void main(String[] args) {
		// Editable variables -- ensure you change these to your application's details
		String strSysUID = "uid=YOURSYSTEMIDGOESHERE,ou=OrgUnitName,o=OrgName";
		String strSysPassword = "YourSystemPasswordGoesHere";
		String strAuthorizationGroup = "LJL_Test";
		String strTrustStorePassword = "YourTrustStorePassword"

		String trustStoreFile = ".\\ADTrust";

		String sLDAPServer = "ldaps://ldap.domain.gTLD:636";
		String strUserBaseDN = "ou=UserOU,o=OrgName";
		String strGroupBaseDN = "ou=GroupOU,o=OrgName";
		String strUserIDSchemaAttribute = "uid=";							// attribute that holds user logon name
		String strGroupMembershipSchemaAttribute = "uniqueMember";			// attribute that holds member list in group object
		// End of editable variables

		System.setProperty("javax.net.ssl.trustStore", trustStoreFile);
		System.setProperty("javax.net.ssl.trustStorePassword", strTrustStorePassword);

		// Obtain UID and PWD from user
		String sUserUID = "";
		String sUserPwd = "";

		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

		System.out.print("Please enter your username: ");

		try{
			sUserUID = in.readLine();
		}catch(Exception er) { er.printStackTrace(); }


		System.out.print("Please enter your password: ");
		try{
			sUserPwd = in.readLine();
		}catch(Exception er) { er.printStackTrace(); }


		// Initial context for system bind
		Hashtable env = new Hashtable(11);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, sLDAPServer);
		env.put(Context.SECURITY_PROTOCOL, "ssl");


		// Authenticate as system ID and password
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, strSysUID);
		env.put(Context.SECURITY_CREDENTIALS, strSysPassword);

		try {
			DirContext ctx = new InitialDirContext(env);

			// Using the system credentials, search for a user matching the logon ID provided by the user
			String sFilter = strUserIDSchemaAttribute + sUserUID;
			NamingEnumeration UserDNAnswer = ctx.search(strUserBaseDN, sFilter, null);

			String sReturnedFQDN = "";
			// If only one record should be returns, validate that exactly one record is located and throw an error otherwise
			while (UserDNAnswer.hasMore()) {
				SearchResult sr = (SearchResult) UserDNAnswer.next();
				// Store the DN of the user re have found
				sReturnedFQDN = sr.getNameInNamespace();
			}

			// Check group membership, can be done after the password is validated if you wish
			// Exaple LDAP filter is "(&(cn=NameOfGroupToCheck)(uniqueMember=FQDNOfUserBeingTested))"
			String sGroupFilter = "(&(cn=" + strAuthorizationGroup + ")(" + strGroupMembershipSchemaAttribute + "=" + sReturnedFQDN + "))";
			NamingEnumeration GroupMembershipAnswer = ctx.search(strGroupBaseDN, sGroupFilter, null);

			String sReturnedGroupDN = "";
			while (GroupMembershipAnswer.hasMore()) {
				SearchResult srGroup = (SearchResult) GroupMembershipAnswer.next();
				sReturnedGroupDN = srGroup.getNameInNamespace();
			}

			ctx.close();
			// If an entry was returned, then the user is a member of the group. We should validate the user's password
			if(sReturnedGroupDN.equals("cn=" + strAuthorizationGroup+ "," + strGroupBaseDN)){
				System.out.println(sReturnedFQDN + " is a member of " + sReturnedGroupDN + " and now we will validate the password.");

				// Now establish a new LDAP connection to validate the credentials supplied
				Hashtable envUser = new Hashtable(11);
				envUser.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
				envUser.put(Context.PROVIDER_URL, sLDAPServer);

				// Authenticate using the searched FQDN for the user and the password provided by the user
				envUser.put(Context.SECURITY_AUTHENTICATION, "simple");
				envUser.put(Context.SECURITY_PRINCIPAL, sReturnedFQDN);
				envUser.put(Context.SECURITY_CREDENTIALS, sUserPwd);

				// Doing this so a login failure throws a code
				try{
					DirContext ctxUser = new InitialDirContext(envUser);
					System.out.println("Successfully authenticated as " + sUserUID);
					ctxUser .close;
				}
				// User credentials failure
				catch (NamingException e) {
					e.printStackTrace();
				}
			}
			// If no group matched the filter, the user is not a group member and an authorisation failure can be returned
			else{
				System.out.println(sReturnedFQDN + " is NOT a member of " + sReturnedGroupDN + " and there is no need to verify the password.");
			}
		}
		// System credentials failure
		catch (NamingException e) {
			e.printStackTrace();
		}
	}
}

