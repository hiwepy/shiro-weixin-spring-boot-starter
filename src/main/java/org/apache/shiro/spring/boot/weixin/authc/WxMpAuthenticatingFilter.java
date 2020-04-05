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
import org.apache.shiro.spring.boot.weixin.token.WxMpAuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

/**
 * 小程序微信认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class WxMpAuthenticatingFilter extends AbstractTrustableAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(WxMpAuthenticatingFilter.class);
    public static final String SPRING_SECURITY_FORM_UNIONID_KEY = "unionid";
    public static final String SPRING_SECURITY_FORM_OPENID_KEY = "openid";

    private String unionidParameter = SPRING_SECURITY_FORM_UNIONID_KEY;
    private String openidParameter = SPRING_SECURITY_FORM_OPENID_KEY;
	
	public WxMpAuthenticatingFilter() {
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
				WxMpLoginRequest loginRequest = objectMapper.readValue(request.getReader(), WxMpLoginRequest.class);
				return new WxMpAuthenticationToken(loginRequest.getUnionid(), loginRequest.getOpenid(), getHost(request));
			} catch (IOException e) {
			}
		}
		return new WxMpAuthenticationToken(obtainUnionid(request), obtainOpenid(request), getHost(request));
	}
	
    protected String obtainUnionid(ServletRequest request) {
        return request.getParameter(unionidParameter);
    }
    
    protected String obtainOpenid(ServletRequest request) {
        return request.getParameter(openidParameter);
    }

	public String getUnionidParameter() {
		return unionidParameter;
	}

	public void setUnionidParameter(String unionidParameter) {
		this.unionidParameter = unionidParameter;
	}

	public String getOpenidParameter() {
		return openidParameter;
	}

	public void setOpenidParameter(String openidParameter) {
		this.openidParameter = openidParameter;
	}

}
