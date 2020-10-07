package de.wyraz.easyauth.provider.ldap;

import java.net.URI;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Value;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;

import de.wyraz.easyauth.model.AuthException;
import de.wyraz.easyauth.model.AuthException.ErrorCode;
import de.wyraz.easyauth.model.User;
import de.wyraz.easyauth.provider.IUserProvider;

/**
 * See https://github.com/authelia/authelia/blob/master/internal/authentication/ldap_user_provider.go
 * @author mwyraz
 */
public class LdapUserProvider implements IUserProvider {
	
	@Value("${ldap.serverUrl}")
	protected URI serverUrl;

	@Value("${ldap.baseDn}")
	protected String baseDn;

	@Value("${ldap.bindDn}")
	protected String bindDn;

	@Value("${ldap.bindPassword}")
	protected String bindPassword;

	@Value("${ldap.usersFilter}")
	protected String usersFilter;

	@Value("${ldap.usernameAttribute}")
	protected String usernameAttribute;

	@Value("${ldap.displayNameAttribute}")
	protected String displayNameAttribute;
	
	@Value("${ldap.emailAttribute}")
	protected String emailAttribute;

	@Value("${ldap.additionalUsersDn:}")
	protected String additionalUsersDn;
	
	@Value("${ldap.groupsFilter}")
	protected String groupsFilter;

	@Value("${ldap.groupNameAttribute}")
	protected String groupNameAttribute;

	@Value("${ldap.additionalGroupsDn:}")
	protected String additionalGroupsDn;
	
	protected LDAPConnection connect() throws LDAPException {
		int port=serverUrl.getPort();
		SocketFactory socketFactory;
		if ("ldaps".equalsIgnoreCase(serverUrl.getScheme())) {
			// ssl ecrypted ldap connection
			if (port<=0) {
				port=636;
			}
			socketFactory=SSLSocketFactory.getDefault();
		} else {
			// plain ldap connection
			if (port<=0) {
				port=389;
			}
			socketFactory=SocketFactory.getDefault();
		}
		return new LDAPConnection(socketFactory,serverUrl.getHost(), port);
	}
	
	public User authenticateUser(String username, String password) throws AuthException {
		try (LDAPConnection ldap=connect()) {
			LdapUser user=findUserByUsername(ldap, username);
			if (user==null) {
				// Log: user not found
				throw new AuthException(ErrorCode.AUTHENTICATION_REQUIRED);
			}
			try {
				// Log: password wrong
				ldap.bind(user.getDn(), password);
			} catch (LDAPException ex) {
				throw new AuthException(ErrorCode.AUTHENTICATION_REQUIRED, ex);
			}
			return user;
		} catch (LDAPException ex) {
			throw new AuthException(ErrorCode.INTERNAL,ex);
		}
	}
	
	protected LdapUser findUserByUsername(LDAPConnection ldap, String username) throws LDAPException {
		ldap.bind(bindDn, bindPassword);
		String filter=usersFilter
				.replace("{usernameAttribute}", usernameAttribute)
				.replace("{emailAttribute}", emailAttribute)
				.replace("{username}", Filter.encodeValue(username)); // username must be encoded for query to prevent injection attacks
		SearchResult result=ldap.search(dn(additionalUsersDn,baseDn), SearchScope.SUB, filter, "*");
		if (result.getEntryCount()==0) {
			return null;
		}
		if (result.getEntryCount()>0) {
			// warn that the name is ambigous
		}
		SearchResultEntry e=result.getSearchEntries().get(0);
		LdapUser user=new LdapUser(e.getDN());
		user.setUsername(e.getAttributeValue(usernameAttribute));
		user.setDisplayName(e.getAttributeValue(displayNameAttribute));
		user.setEmail(e.getAttributeValue(emailAttribute));
		
		filter=groupsFilter
				.replace("{groupNameAttribute}", groupNameAttribute)
				.replace("{userDn}",user.getDn())
				.replace("{username}",user.getUsername());
		
		for (SearchResultEntry ge: ldap.search(dn(additionalGroupsDn,baseDn), SearchScope.SUB, filter, "*").getSearchEntries()) {
			user.getGroups().add(ge.getAttributeValue(groupNameAttribute));
		}
		
		return user;
	}
	
	protected String dn(String... parts) {
		StringBuilder sb=new StringBuilder();
		for (String part: parts) {
			if (!Strings.isBlank(part)) {
				if (sb.length()>0) sb.append(",");
				sb.append(part);
			}
		}
		return sb.toString();
	}
}
