package org.apache.shiro.spring.boot.weixin.realm;

import java.util.Objects;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.weixin.authc.WxMpLoginRequest;
import org.apache.shiro.spring.boot.weixin.token.WxMpAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import me.chanjar.weixin.common.bean.WxOAuth2UserInfo;
import me.chanjar.weixin.common.bean.oauth2.WxOAuth2AccessToken;
import me.chanjar.weixin.common.error.WxErrorException;
import me.chanjar.weixin.mp.api.WxMpService;
import me.chanjar.weixin.mp.bean.result.WxMpUser;

/**
 * WeiXin AuthorizingRealm
 * https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Official_Accounts/official_account_website_authorization.html
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Slf4j
public class WxMpAuthorizingRealm extends AbstractAuthorizingRealm {

	private final WxMpService wxMpService;

    public WxMpAuthorizingRealm(final WxMpService wxMpService) {
        this.wxMpService = wxMpService;
    }

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return WxMpAuthenticationToken.class;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		log.info("Handle authentication token {}.", token);

    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;
    	try {

    		WxMpAuthenticationToken loginToken =  (WxMpAuthenticationToken) token;
			WxMpLoginRequest loginRequest = (WxMpLoginRequest) loginToken.getPrincipal();

			// 表示需要根据code获取会话信息
			if (StringUtils.hasText(loginRequest.getCode()) ) {
				WxOAuth2AccessToken accessToken = getWxMpService().getOAuth2Service().getAccessToken(loginRequest.getCode());
				if (Objects.nonNull(accessToken)) {
					loginRequest.setAccessToken(accessToken);
					loginRequest.setOpenid(accessToken.getOpenId());
					loginRequest.setUnionid(accessToken.getUnionId());
				}
			}

			if(Objects.isNull(loginRequest.getUserInfo()) && Objects.nonNull(loginRequest.getAccessToken()) ) {
				WxOAuth2UserInfo userInfo = getWxMpService().getOAuth2Service().getUserInfo(loginRequest.getAccessToken(), loginRequest.getLang());
				if (Objects.nonNull(userInfo)) {
					loginRequest.setUserInfo(userInfo);
				}
			}

			info = getRepository().getAuthenticationInfo(loginToken);

		} catch (AuthenticationException e) {
			ex = e;
		} catch (WxErrorException e) {
			ex = new AuthenticationException(e);
		}

		//调用事件监听器
		if(getRealmsListeners() != null && getRealmsListeners().size() > 0){
			for (AuthorizingRealmListener realmListener : getRealmsListeners()) {
				if(ex != null || null == info){
					realmListener.onFailure(this, token, ex);
				}else{
					realmListener.onSuccess(this, info);
				}
			}
		}

		if(ex != null){
			throw ex;
		}

		return info;
	}

	public WxMpService getWxMpService() {
		return wxMpService;
	}

}
