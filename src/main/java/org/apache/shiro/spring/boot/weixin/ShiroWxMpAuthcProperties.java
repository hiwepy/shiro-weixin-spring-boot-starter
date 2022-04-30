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
package org.apache.shiro.spring.boot.weixin;

import org.apache.shiro.spring.boot.weixin.authc.WxMpAuthenticatingFilter;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(ShiroWxMpAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class ShiroWxMpAuthcProperties {

	public static final String PREFIX = "shiro.weixin.mp";

	/** the code parameter name. Defaults to "code". */
    private String codeParameter = WxMpAuthenticatingFilter.SPRING_SECURITY_FORM_CODE_KEY;

    /** the token parameter name. Defaults to "token". */
    private String tokenParameter = WxMpAuthenticatingFilter.SPRING_SECURITY_FORM_TOKEN_KEY;
    /**
     * The URL to where the user will be redirected after logout.
     */
	private String redirectUrl = LogoutFilter.DEFAULT_REDIRECT_URL;

}
