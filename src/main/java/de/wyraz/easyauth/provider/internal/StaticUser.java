package de.wyraz.easyauth.provider.internal;

import de.wyraz.easyauth.model.User;

public class StaticUser extends User {

	protected final String passwordHash;

	public StaticUser(String username, String displayName, String email, String passwordHash) {
		this.username = username;
		this.displayName = displayName;
		this.email = email;
		this.passwordHash = passwordHash;
	}

}
