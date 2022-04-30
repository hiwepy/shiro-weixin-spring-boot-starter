package org.apache.shiro.spring.boot.weixin.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class WxJsCodeInvalidException extends AuthenticationException {

	public WxJsCodeInvalidException() {
		super();
	}

	public WxJsCodeInvalidException(String message, Throwable cause) {
		super(message, cause);
	}

	public WxJsCodeInvalidException(String message) {
		super(message);
	}

	public WxJsCodeInvalidException(Throwable cause) {
		super(cause);
	}

}
