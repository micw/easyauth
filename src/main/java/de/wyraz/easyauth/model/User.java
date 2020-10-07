package de.wyraz.easyauth.model;

import java.util.Set;
import java.util.TreeSet;

public class User {
	protected String username;
	protected String displayName;
	protected String email;
	protected Set<String> groups=new TreeSet<>();
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getDisplayName() {
		return displayName;
	}
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public Set<String> getGroups() {
		return groups;
	}
	
	@Override
	public String toString() {
		return "User["+fieldsToString()+"]";
	}
	public String fieldsToString() {
		return "username="+username+",email="+email+",groups="+groups;
	}
	

}

