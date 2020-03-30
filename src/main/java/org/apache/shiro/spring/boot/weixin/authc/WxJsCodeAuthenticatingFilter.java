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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.AbstractTrustableAuthenticatingFilter;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.weixin.token.WxJsCodeLoginToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

/**
 * 小程序微信认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class WxJsCodeAuthenticatingFilter extends AbstractTrustableAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(WxJsCodeAuthenticatingFilter.class);
    public static final String SPRING_SECURITY_FORM_JSCODE_KEY = "jscode";
    public static final String SPRING_SECURITY_FORM_SIGNATURE_KEY = "signature";
    public static final String SPRING_SECURITY_FORM_RAWDATA_KEY = "rawData";
    public static final String SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY = "encryptedData";
    public static final String SPRING_SECURITY_FORM_IV_KEY = "iv";
	
    private String jscodeParameter = SPRING_SECURITY_FORM_JSCODE_KEY;
    private String signatureParameter = SPRING_SECURITY_FORM_SIGNATURE_KEY;
    private String rawDataParameter = SPRING_SECURITY_FORM_RAWDATA_KEY;
    private String encryptedDataParameter = SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY;
    private String ivParameter = SPRING_SECURITY_FORM_IV_KEY;
	
	public WxJsCodeAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		// 判断是否无状态
		if (isSessionStateless()) {
			// Step 1、生成 Shiro Token 
			AuthenticationToken token = createToken(request, response);
			try {
				//Step 2、委托给Realm进行登录  
				Subject subject = getSubject(request, response);
				subject.login(token);
				//Step 3、执行授权成功后的函数
				return onAccessSuccess(token, subject, request, response);
			} catch (AuthenticationException e) {
				//Step 4、执行授权失败后的函数
				return onAccessFailure(token, e, request, response);
			}
		}
		return super.isAccessAllowed(request, response, mappedValue);
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		
		// 1、判断是否登录请求 
		if (isLoginRequest(request, response)) {
			
			if (isLoginSubmission(request, response)) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Login submission detected.  Attempting to execute login.");
				}
				return executeLogin(request, response);
			} else {
				String mString = "Authentication url [" + getLoginUrl() + "] Not Http Post request.";
				if (LOG.isTraceEnabled()) {
					LOG.trace(mString);
				}
				
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_BAD_REQUEST);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
				
				// Response Authentication status information
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
				
				return false;
			}
		}
		// 2、未授权情况
		else {
			
			String mString = "Attempting to access a path which requires authentication. ";
			if (LOG.isTraceEnabled()) { 
				LOG.trace(mString);
			}
			
			// Ajax 请求：响应json数据对象
			if (WebUtils.isAjaxRequest(request)) {
				
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_UNAUTHORIZED);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
				
				// Response Authentication status information
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
				
				return false;
			}
			// 普通请求：重定向到登录页
			saveRequestAndRedirectToLogin(request, response);
			return false;
		}
	}
	
	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
		// Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			try {
				WxJsCodeLoginRequest loginRequest = objectMapper.readValue(request.getReader(), WxJsCodeLoginRequest.class);
				return new WxJsCodeLoginToken(loginRequest.getJscode(), loginRequest.getSignature(), loginRequest.getRawData(),
						loginRequest.getEncryptedData(), loginRequest.getIv(), getHost(request));
			} catch (IOException e) {
			}
		}
		
		return new WxJsCodeLoginToken(obtainJscode(request), obtainSignature(request), obtainRawData(request), 
				obtainEncryptedData(request), obtainIv(request), getHost(request));
	}

	protected String obtainJscode(ServletRequest request) {
        return request.getParameter(jscodeParameter);
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

}