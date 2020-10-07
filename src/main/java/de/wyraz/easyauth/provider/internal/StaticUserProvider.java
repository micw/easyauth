package de.wyraz.easyauth.provider.internal;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Value;

import de.wyraz.easyauth.model.AuthException;
import de.wyraz.easyauth.model.AuthException.ErrorCode;
import de.wyraz.easyauth.model.User;
import de.wyraz.easyauth.provider.IUserProvider;
import de.wyraz.easyauth.util.PasswordHelper;

public class StaticUserProvider implements IUserProvider {
	
	@Value("${static.users}")
	protected void setUsers(String usersAsString) {
		for (StringTokenizer st = new StringTokenizer(usersAsString," \t\r\n");st.hasMoreTokens();) {
			String userAsString=st.nextToken().trim();
			if (Strings.isEmpty(userAsString)) {
				continue;
			}
			String[] userdata=userAsString.split(":",5);
			if (userdata.length<4) {
				// Log: invalid user spec
				continue;
			}
			
			StaticUser user=new StaticUser(userdata[0], userdata[1], userdata[2], userdata[3]);
			
			if (userdata.length==5) {
				for (String group: userdata[4].split(",")) {
					group=group.trim();
					if (Strings.isEmpty(group)) {
						continue;
					}
					user.getGroups().add(group);
				}
			}
			
			usersByUsername.put(user.getUsername(), user);
		}
	}
	
	protected Map<String,StaticUser> usersByUsername=new HashMap<>();
	
	@Override
	public User authenticateUser(String username, String password) throws AuthException {
		StaticUser user=usersByUsername.get(username);
		if (user!=null && PasswordHelper.checkPassword(user.passwordHash, password)) {
			return user;
		}
		throw new AuthException(ErrorCode.AUTHENTICATION_REQUIRED);
	}

}
