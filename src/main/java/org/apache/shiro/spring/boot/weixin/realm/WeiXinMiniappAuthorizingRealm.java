package org.apache.shiro.spring.boot.weixin.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.weixin.token.WeiXinLoginToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.binarywang.wx.miniapp.api.WxMaUserService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import me.chanjar.weixin.common.error.WxErrorException;

/**
 * WeiXin AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class WeiXinMiniappAuthorizingRealm extends AbstractAuthorizingRealm {
	
	private static final Logger LOG = LoggerFactory.getLogger(WeiXinMiniappAuthorizingRealm.class);
	private final WxMaUserService wxMaUserService;
	 
    public WeiXinMiniappAuthorizingRealm(final WxMaUserService wxMaUserService) {
        this.wxMaUserService = wxMaUserService;
    }
    
	@Override
	public Class<?> getAuthenticationTokenClass() {
		return WeiXinLoginToken.class;// 此Realm只支持SmsLoginToken
	}
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		LOG.info("Handle authentication token {}.", new Object[] { token });
    	
    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;
    	
    	try {
    		
    		WeiXinLoginToken weixinToken =  (WeiXinLoginToken) token;
    		
    		// 根据jscode获取会话信息
			WxMaJscode2SessionResult sessionResult = getWxMaUserService().getSessionInfo(weixinToken.getJscode());
			if (null == sessionResult) {
				
			}
			
			weixinToken.setOpenid(sessionResult.getOpenid());
			weixinToken.setUnionid(sessionResult.getUnionid());
			weixinToken.setSessionKey(sessionResult.getSessionKey());
			
			
				
			info = getRepository().getAuthenticationInfo(weixinToken);
    		
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
	
	public WxMaUserService getWxMaUserService() {
		return wxMaUserService;
	}

}
