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
package org.apache.shiro.spring.boot.weixin.token;

import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.spring.boot.weixin.authc.WxMpLoginRequest;

import me.chanjar.weixin.mp.bean.result.WxMpUser;

/**
 * 微信公众号 Login Token
 * 
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public class WxMpAuthenticationToken extends DefaultAuthenticationToken {
	
	protected WxMpLoginRequest principal;
	
	/**
	 * 第三方平台UnionID（通常指第三方账号体系下用户的唯一ID）
	 */
	protected String unionid;
	/**
	 * 第三方平台OpenID（通常指第三方账号体系下某应用中用户的唯一ID）
	 */
	protected String openid;
	/**
	 * 用户信息
	 */
	protected WxMpUser userInfo;
	
	public WxMpAuthenticationToken( WxMpLoginRequest request, String host) {
		super(request.getUsername(),  request.getPassword(), true, host);
		this.principal = request;
		this.unionid = request.getUnionid();
		this.openid = request.getOpenid();
		this.setHost(host);
	}
	
	@Override
	public WxMpLoginRequest getPrincipal() {
		return principal;
	}

	public String getUnionid() {
		return unionid;
	}

	public void setUnionid(String unionid) {
		this.unionid = unionid;
	}

	public String getOpenid() {
		return openid;
	}

	public void setOpenid(String openid) {
		this.openid = openid;
	}

	public WxMpUser getUserInfo() {
		return userInfo;
	}

	public void setUserInfo(WxMpUser userInfo) {
		this.userInfo = userInfo;
	}

}
