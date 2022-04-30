/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.weixin.authc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.AbstractTrustableAuthenticatingFilter;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.weixin.exception.WxJsCodeInvalidException;
import org.apache.shiro.spring.boot.weixin.token.WxMaAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;
import org.springframework.util.StringUtils;

/**
 * 小程序微信认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Slf4j
public class WxMaAuthenticatingFilter extends AbstractTrustableAuthenticatingFilter {

	public static final String SPRING_SECURITY_FORM_JSCODE_KEY = "jscode";
	public static final String SPRING_SECURITY_FORM_SESSIONKEY_KEY = "sessionKey";
	public static final String SPRING_SECURITY_FORM_UNIONID_KEY = "unionid";
	public static final String SPRING_SECURITY_FORM_OPENID_KEY = "openid";
	public static final String SPRING_SECURITY_FORM_SIGNATURE_KEY = "signature";
	public static final String SPRING_SECURITY_FORM_RAWDATA_KEY = "rawData";
	public static final String SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY = "encryptedData";
	public static final String SPRING_SECURITY_FORM_IV_KEY = "iv";
	public static final String SPRING_SECURITY_FORM_TOKEN_KEY = "token";

	private String jscodeParameter = SPRING_SECURITY_FORM_JSCODE_KEY;
	private String sessionKeyParameter = SPRING_SECURITY_FORM_SESSIONKEY_KEY;
	private String unionidParameter = SPRING_SECURITY_FORM_UNIONID_KEY;
	private String openidParameter = SPRING_SECURITY_FORM_OPENID_KEY;
	private String signatureParameter = SPRING_SECURITY_FORM_SIGNATURE_KEY;
	private String rawDataParameter = SPRING_SECURITY_FORM_RAWDATA_KEY;
	private String encryptedDataParameter = SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY;
	private String ivParameter = SPRING_SECURITY_FORM_IV_KEY;
	private String tokenParameter = SPRING_SECURITY_FORM_TOKEN_KEY;

	public WxMaAuthenticatingFilter() {
		super();
	}

	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		return false;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {

		if (isLoginSubmission(request, response)) {
			if (log.isTraceEnabled()) {
				log.trace("Login submission detected.  Attempting to execute login.");
			}
			return executeLogin(request, response);
		} else {
			String mString = "Authentication url [" + getLoginUrl() + "] Not Http Post request.";
			if (log.isTraceEnabled()) {
				log.trace(mString);
			}

			WebUtils.toHttp(response).setStatus(HttpStatus.SC_OK);
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setCharacterEncoding(StandardCharsets.UTF_8.toString());

			// Response Authentication status information
			JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(HttpStatus.SC_BAD_REQUEST, mString));

			return false;
		}

	}



	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
		// Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			try {
				WxMaLoginRequest loginRequest = objectMapper.readValue(request.getReader(), WxMaLoginRequest.class);
				if ( !StringUtils.hasText(loginRequest.getJscode())) {
					log.debug("No jscode found in request.");
					throw new WxJsCodeInvalidException("No jscode found in request.");
				}
				return new WxMaAuthenticationToken(loginRequest, getHost(request));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		String jscode = obtainJscode(request);
		if ( !StringUtils.hasText(jscode)) {
			log.debug("No jscode found in request.");
			throw new WxJsCodeInvalidException("No jscode found in request.");
		}
		String sessionKey = obtainSessionKey(request);
		String unionid = obtainUnionid(request);
		String openid = obtainOpenid(request);
		String signature = obtainSignature(request);
		String rawData = obtainRawData(request);
		String encryptedData = obtainEncryptedData(request);
		String iv = obtainIv(request);
		String token = obtainToken(request);

		if (sessionKey == null) {
			sessionKey = "";
		}
		if (unionid == null) {
			unionid = "";
		}
		if (openid == null) {
			openid = "";
		}
		if (signature == null) {
			signature = "";
		}
		if (rawData == null) {
			rawData = "";
		}
		if (encryptedData == null) {
			encryptedData = "";
		}
		if (iv == null) {
			iv = "";
		}
		if (token == null) {
			token = "";
		}
        WxMaLoginRequest loginRequest = new WxMaLoginRequest(jscode, sessionKey, unionid, openid,
				signature, rawData, encryptedData, iv, token);
		return new WxMaAuthenticationToken(loginRequest, getHost(request));
	}

	protected String obtainJscode(ServletRequest request) {
        return request.getParameter(jscodeParameter);
    }

	protected String obtainSessionKey(ServletRequest request) {
        return request.getParameter(sessionKeyParameter);
    }

	protected String obtainUnionid(ServletRequest request) {
        return request.getParameter(unionidParameter);
    }

	protected String obtainOpenid(ServletRequest request) {
        return request.getParameter(openidParameter);
    }


	protected String obtainSignature(ServletRequest request) {
        return request.getParameter(signatureParameter);
    }

	protected String obtainRawData(ServletRequest request) {
        return request.getParameter(rawDataParameter);
    }

	protected String obtainEncryptedData(ServletRequest request) {
        return request.getParameter(encryptedDataParameter);
    }

    protected String obtainIv(ServletRequest request) {
        return request.getParameter(ivParameter);
    }

	protected String obtainToken(ServletRequest request) {
		return request.getParameter(tokenParameter);
	}

	public String getJscodeParameter() {
		return jscodeParameter;
	}

	public void setJscodeParameter(String jscodeParameter) {
		this.jscodeParameter = jscodeParameter;
	}

	public String getSignatureParameter() {
		return signatureParameter;
	}

	public void setSignatureParameter(String signatureParameter) {
		this.signatureParameter = signatureParameter;
	}

	public String getRawDataParameter() {
		return rawDataParameter;
	}

	public void setRawDataParameter(String rawDataParameter) {
		this.rawDataParameter = rawDataParameter;
	}

	public String getEncryptedDataParameter() {
		return encryptedDataParameter;
	}

	public void setEncryptedDataParameter(String encryptedDataParameter) {
		this.encryptedDataParameter = encryptedDataParameter;
	}

	public String getIvParameter() {
		return ivParameter;
	}

	public void setIvParameter(String ivParameter) {
		this.ivParameter = ivParameter;
	}

	public void setTokenParameter(String tokenParameter) {
		this.tokenParameter = tokenParameter;
	}

	public String getTokenParameter() {
		return tokenParameter;
	}

}
