package de.wyraz.easyauth.controller;

import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import de.wyraz.easyauth.model.AuthException;
import de.wyraz.easyauth.model.AuthException.ErrorCode;
import de.wyraz.easyauth.provider.IUserProvider;
import de.wyraz.easyauth.provider.ldap.LdapUserProvider;
import de.wyraz.easyauth.model.User;

@Controller
public class BasicAuthController {
	
	@Autowired
	protected IUserProvider userProvider;
	
	@GetMapping("/auth/basic")
	public ResponseEntity<String> handleBasicAuth(HttpServletRequest request,
			@RequestParam(name = "realmName", defaultValue = "restricted") String realmName,
			@RequestParam(name = "allowGroups", required = false) String allowGroups,
			@RequestParam(name = "requireGroups", required = false) String requireGroups
			) {
		ErrorCode errorCode=ErrorCode.AUTHENTICATION_REQUIRED;
		Throwable errorCause=null;
		
		String[] userAndPassword=extractBasicAuth(request.getHeader("Authorization"));
		if (userAndPassword!=null) {
			try {
				User user=userProvider.authenticateUser(userAndPassword[0], userAndPassword[1]);
				if (user!=null) {
					checkUserGroups(user,allowGroups,false);
					checkUserGroups(user,requireGroups,true);
					
					return ResponseEntity
							.status(HttpStatus.OK)
							.body("Welcome "+user.getDisplayName());
				}
			} catch (AuthException ex) {
				errorCode=ex.getErrorCode();
				errorCause=ex;
			}
		}
		
		if (errorCode==ErrorCode.AUTHENTICATION_REQUIRED) {
			return ResponseEntity
					.status(HttpStatus.UNAUTHORIZED)
					.header("WWW-Authenticate", "Basic realm=\""+realmName+"\"")
					.body(errorCode.name());
		} else {
			return ResponseEntity
					.status(HttpStatus.FORBIDDEN)
					.body(errorCode.name());
		}
	}
	
	protected String[] extractBasicAuth(String authHeader) {
		if (authHeader==null || !authHeader.toLowerCase().startsWith("basic ")) {
			return null;
		}
		authHeader=authHeader.substring(6).trim();
		try {
			authHeader=new String(Base64.getDecoder().decode(authHeader));
		} catch (IllegalArgumentException ex) {
			// Log: invalid base64
			return null;
		}
		String[] userAndPassword=authHeader.split(":",2);
		if (userAndPassword.length!=2) {
			return null;
		}
		return userAndPassword;
	}
	protected void checkUserGroups(User user, String groups, boolean requireAllGroups) throws AuthException {
		if (groups==null || groups.isEmpty()) {
			// nothing to check
			return;
		}
		boolean hasOneGroup=false;
		boolean hasAllGroups=true;
		for (String group: groups.split(",")) {
			if (Strings.isBlank(group)) {
				continue;
			}
			if (user.getGroups().contains(group)) {
				hasOneGroup=true;
			} else {
				hasAllGroups=false;
			}
		}
		if (requireAllGroups) {
			if (!hasAllGroups) {
				throw new AuthException(ErrorCode.NOT_AUTHORIZED);
			}
		} else {
			if (!hasOneGroup) {
				throw new AuthException(ErrorCode.NOT_AUTHORIZED);
			}
		}
		return;
	}

}

