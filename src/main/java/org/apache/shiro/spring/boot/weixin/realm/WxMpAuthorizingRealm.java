package org.apache.shiro.spring.boot.weixin.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.weixin.token.WxMpAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import me.chanjar.weixin.common.error.WxErrorException;
import me.chanjar.weixin.mp.api.WxMpService;
import me.chanjar.weixin.mp.bean.result.WxMpUser;

/**
 * WeiXin AuthorizingRealm
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
    	
    	try {
    		
    		WxMpAuthenticationToken loginToken =  (WxMpAuthenticationToken) token;
    		
    		WxMpUser userInfo = getWxMpService().getUserService().userInfo(loginToken.getOpenid());
			if (null == userInfo) {
				
			}
			
			loginToken.setOpenid(userInfo.getOpenId());
			loginToken.setUnionid(userInfo.getUnionId());
			loginToken.setUserInfo(userInfo);
			
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
