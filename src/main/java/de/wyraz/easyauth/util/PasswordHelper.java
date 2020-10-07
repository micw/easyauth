package de.wyraz.easyauth.util;

import org.springframework.security.crypto.bcrypt.BCrypt;

public class PasswordHelper {

	public static boolean checkPassword(String passwordHash, String plaintextPassword) {
		if (passwordHash.toLowerCase().startsWith("{plain}")) {
			return passwordHash.substring(7).equals(plaintextPassword);
		}
		if (passwordHash.toLowerCase().startsWith("{bcrypt}")) {
			return BCrypt.checkpw(plaintextPassword, passwordHash.substring(8));
		}
		return false;
	}

}
