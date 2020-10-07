package de.wyraz.easyauth.provider.ldap;

import de.wyraz.easyauth.model.User;

public class LdapUser extends User {

	protected final String dn;
	
	public LdapUser(String dn) {
		this.dn=dn;
	}
	
	public String getDn() {
		return dn;
	}

}
