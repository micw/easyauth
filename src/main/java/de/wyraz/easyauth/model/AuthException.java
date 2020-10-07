package de.wyraz.easyauth.model;

public class AuthException extends Exception {
	
	private static final long serialVersionUID = 1L;
	
	public enum ErrorCode {
		INTERNAL, // some other error occured
		AUTHENTICATION_REQUIRED, // user credentials are missing or wrong
		NOT_AUTHORIZED, // user is not allowed to access this ressource
	}
	
	protected final ErrorCode errorCode;
	
	public AuthException(ErrorCode errorCode) {
		super(errorCode.name());
		this.errorCode=errorCode;
	}
	public AuthException(ErrorCode errorCode, Throwable cause) {
		this(errorCode);
		initCause(cause);
	}
	
	public ErrorCode getErrorCode() {
		return errorCode;
	}
}
