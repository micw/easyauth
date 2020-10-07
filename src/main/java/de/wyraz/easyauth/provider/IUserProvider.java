package de.wyraz.easyauth.provider;

import de.wyraz.easyauth.model.AuthException;
import de.wyraz.easyauth.model.User;

public interface IUserProvider {
	/**
	 * Authenticate the user against the backend.
	 * This method should either return a user or throw an AuthException
	 */
	public User authenticateUser(String username, String password) throws AuthException;
}
