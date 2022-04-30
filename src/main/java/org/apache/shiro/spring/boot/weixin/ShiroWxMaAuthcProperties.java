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

import org.apache.shiro.spring.boot.weixin.authc.WxMaAuthenticatingFilter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(ShiroWxMaAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class ShiroWxMaAuthcProperties {

	public static final String PREFIX = "shiro.weixin.ma";

	/** the jscode parameter name. Defaults to "jscode". */
    private String jscodeParameter = WxMaAuthenticatingFilter.SPRING_SECURITY_FORM_JSCODE_KEY;
    /** the signature parameter name. Defaults to "signature". */
    private String signatureParameter = WxMaAuthenticatingFilter.SPRING_SECURITY_FORM_SIGNATURE_KEY;
    /** the rawData parameter name. Defaults to "rawData". */
    private String rawDataParameter = WxMaAuthenticatingFilter.SPRING_SECURITY_FORM_RAWDATA_KEY;
    /** the encryptedData parameter name. Defaults to "encryptedData". */
    private String encryptedDataParameter = WxMaAuthenticatingFilter.SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY;
    /** the iv parameter name. Defaults to "iv". */
    private String ivParameter = WxMaAuthenticatingFilter.SPRING_SECURITY_FORM_IV_KEY;
    /** the unionid parameter name. Defaults to "unionid". */
    private String unionidParameter = WxMaAuthenticatingFilter.SPRING_SECURITY_FORM_UNIONID_KEY;
    /** the openid parameter name. Defaults to "openid". */
    private String openidParameter = WxMaAuthenticatingFilter.SPRING_SECURITY_FORM_OPENID_KEY;
    /** the token parameter name. Defaults to "token". */
    private String tokenParameter = WxMaAuthenticatingFilter.SPRING_SECURITY_FORM_TOKEN_KEY;

}
