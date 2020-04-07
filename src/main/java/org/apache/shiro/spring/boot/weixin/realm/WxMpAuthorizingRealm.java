package org.apache.shiro.spring.boot.weixin.realm;

import java.util.Objects;

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

import me.chanjar.weixin.common.error.WxErrorException;
import me.chanjar.weixin.mp.api.WxMpService;
import me.chanjar.weixin.mp.bean.result.WxMpOAuth2AccessToken;
import me.chanjar.weixin.mp.bean.result.WxMpUser;

/**
 * WeiXin AuthorizingRealm
 * https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Official_Accounts/official_account_website_authorization.html
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class WxMpAuthorizingRealm extends AbstractAuthorizingRealm {
	
	private static final Logger LOG = LoggerFactory.getLogger(WxMpAuthorizingRealm.class);
	private final WxMpService wxMpService;
	 
    public WxMpAuthorizingRealm(final WxMpService wxMpService) {
        this.wxMpService = wxMpService;
    }
    
	@Override
	public Class<?> getAuthenticationTokenClass() {
		return WxMpAuthenticationToken.class;// 此Realm只支持SmsLoginToken
	}
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		LOG.info("Handle authentication token {}.", new Object[] { token });
    	
    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;

    	WxMpLoginRequest loginRequest = (WxMpLoginRequest) token.getPrincipal();
    	
    	try {
    		
    		WxMpAuthenticationToken loginToken =  (WxMpAuthenticationToken) token;
    		loginToken.setCode(loginRequest.getCode());
    		loginToken.setOpenid(loginRequest.getOpenid());
			loginToken.setUnionid(loginRequest.getUnionid());
			loginToken.setAccessToken(loginRequest.getAccessToken());
			loginToken.setUserInfo(loginRequest.getUserInfo());
			
			// 表示需要根据code获取会话信息
        	if ( Objects.isNull(loginRequest.getAccessToken()) && StringUtils.hasText(loginRequest.getCode()) ) {
        		WxMpOAuth2AccessToken accessToken = getWxMpService().oauth2getAccessToken(loginRequest.getCode());
    			if (null != accessToken) {
    				loginToken.setAccessToken(accessToken);
    			}
     		}
			
        	if(Objects.isNull(loginRequest.getUserInfo()) && !Objects.isNull(loginRequest.getAccessToken()) ) {
				try {
					WxMpUser userInfo = getWxMpService().oauth2getUserInfo(loginToken.getAccessToken(), loginRequest.getLang());
					if (null == userInfo) {
						loginToken.setUserInfo(userInfo);
					}
				} catch (Exception e) {
					throw new AuthenticationException(e);
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
