package org.apache.shiro.spring.boot.weixin.realm;

import java.util.Objects;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.weixin.authc.WxJsCodeLoginRequest;
import org.apache.shiro.spring.boot.weixin.token.WxJsCodeAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import cn.binarywang.wx.miniapp.api.WxMaService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;
import me.chanjar.weixin.common.error.WxErrorException;

/**
 * WeiXin AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class WxJsCodeAuthorizingRealm extends AbstractAuthorizingRealm {
	
	private static final Logger LOG = LoggerFactory.getLogger(WxJsCodeAuthorizingRealm.class);
	private final WxMaService wxMaService;
	 
    public WxJsCodeAuthorizingRealm(final WxMaService wxMaService) {
        this.wxMaService = wxMaService;
    }
    
	@Override
	public Class<?> getAuthenticationTokenClass() {
		return WxJsCodeAuthenticationToken.class;// 此Realm只支持SmsLoginToken
	}
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		LOG.info("Handle authentication token {}.", new Object[] { token });
    	
    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;

    	WxJsCodeLoginRequest loginRequest = (WxJsCodeLoginRequest) token.getPrincipal();
    	
    	try {
    		
    		WxJsCodeAuthenticationToken loginToken =  (WxJsCodeAuthenticationToken) token;
        	loginToken.setOpenid(loginRequest.getOpenid());
			loginToken.setUnionid(loginRequest.getUnionid());
			loginToken.setSessionKey(loginRequest.getSessionKey());
			loginToken.setUserInfo(loginRequest.getUserInfo());
			
        	// 表示需要根据jscode获取会话信息
        	if (!StringUtils.hasText(loginRequest.getSessionKey()) && StringUtils.hasText(loginRequest.getJscode()) ) {
        		WxMaJscode2SessionResult sessionResult = getWxMaService().jsCode2SessionInfo(loginRequest.getJscode());
    			if (null != sessionResult) {
    				loginToken.setOpenid(sessionResult.getOpenid());
    				loginToken.setUnionid(sessionResult.getUnionid());
    				loginToken.setSessionKey(sessionResult.getSessionKey());
    			}
     		}
			
			if(StringUtils.hasText(loginRequest.getSessionKey()) && StringUtils.hasText(loginRequest.getEncryptedData()) && StringUtils.hasText(loginRequest.getIv()) ) {
				// 解密手机号码信息
				WxMaPhoneNumberInfo phoneNumberInfo = getWxMaService().getUserService().getPhoneNoInfo(loginRequest.getSessionKey(), loginRequest.getEncryptedData(), loginRequest.getIv());
				if ( !Objects.isNull(phoneNumberInfo) && StringUtils.hasText(phoneNumberInfo.getPhoneNumber())) {
					loginToken.setPhoneNumberInfo(phoneNumberInfo);
			    }
			}
			if(Objects.isNull(loginRequest.getUserInfo()) && StringUtils.hasText(loginRequest.getSessionKey()) && StringUtils.hasText(loginRequest.getEncryptedData()) && StringUtils.hasText(loginRequest.getIv())) {
				// 解密用户信息
				WxMaUserInfo userInfo = getWxMaService().getUserService().getUserInfo(loginRequest.getSessionKey(), loginRequest.getEncryptedData(), loginRequest.getIv() );
			    if (null == userInfo) {
			    	loginToken.setUserInfo(userInfo);
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
	
	public WxMaService getWxMaService() {
		return wxMaService;
	}

}
