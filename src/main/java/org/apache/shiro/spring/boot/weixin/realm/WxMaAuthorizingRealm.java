package org.apache.shiro.spring.boot.weixin.realm;

import java.util.Objects;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.weixin.authc.WxMaLoginRequest;
import org.apache.shiro.spring.boot.weixin.token.WxMaAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import cn.binarywang.wx.miniapp.api.WxMaService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;

/**
 * WeiXin AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Slf4j
public class WxMaAuthorizingRealm extends AbstractAuthorizingRealm {

	private final WxMaService wxMaService;

    public WxMaAuthorizingRealm(final WxMaService wxMaService) {
        this.wxMaService = wxMaService;
    }

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return WxMaAuthenticationToken.class;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		log.info("Handle authentication token {}.", token);

    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;

    	try {

    		WxMaAuthenticationToken loginToken =  (WxMaAuthenticationToken) token;
			WxMaLoginRequest loginRequest = (WxMaLoginRequest) loginToken.getPrincipal();

			// 表示需要根据jscode获取会话信息
			if (StringUtils.hasText(loginRequest.getJscode()) ) {
				WxMaJscode2SessionResult sessionResult = getWxMaService().jsCode2SessionInfo(loginRequest.getJscode());
				if (null != sessionResult) {
					loginRequest.setOpenid(sessionResult.getOpenid());
					loginRequest.setUnionid(sessionResult.getUnionid());
					loginRequest.setSessionKey(sessionResult.getSessionKey());
				}
			}

			if(StringUtils.hasText(loginRequest.getSessionKey()) && StringUtils.hasText(loginRequest.getEncryptedData()) && StringUtils.hasText(loginRequest.getIv()) ) {
				try {
					// 解密手机号码信息
					WxMaPhoneNumberInfo phoneNumberInfo = getWxMaService().getUserService().getPhoneNoInfo(loginRequest.getSessionKey(), loginRequest.getEncryptedData(), loginRequest.getIv());
					if ( Objects.nonNull(phoneNumberInfo) && StringUtils.hasText(phoneNumberInfo.getPhoneNumber())) {
						loginRequest.setPhoneNumberInfo(phoneNumberInfo);
					}
				} catch (Exception e) {
					log.error(e.getMessage());
				}
			}
			if(Objects.isNull(loginRequest.getUserInfo()) && StringUtils.hasText(loginRequest.getSessionKey()) && StringUtils.hasText(loginRequest.getEncryptedData()) && StringUtils.hasText(loginRequest.getIv())) {
				try {
					// 解密用户信息
					WxMaUserInfo userInfo = getWxMaService().getUserService().getUserInfo(loginRequest.getSessionKey(), loginRequest.getEncryptedData(), loginRequest.getIv() );
					if (Objects.nonNull(userInfo)) {
						loginRequest.setUserInfo(userInfo);
					}
				} catch (Exception e) {
					throw new AuthenticationException("微信登录认证失败.", e);
				}
			}

			info = getRepository().getAuthenticationInfo(loginToken);

		} catch (AuthenticationException e) {
			ex = e;
		} catch (Exception e) {
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

	public WxMaService getWxMaService() {
		return wxMaService;
	}

}
