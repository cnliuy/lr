/*******************************************************************************
 * Copyright (c) 2005, 2014 springside.github.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *******************************************************************************/
package com.job.lr.service.account;

import java.io.Serializable;

import javax.annotation.PostConstruct;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;

import com.job.lr.entity.User;
import com.job.lr.filter.HmacSHA256Utils;
import com.job.lr.filter.StatelessToken;

import org.springside.modules.utils.Encodes;

import com.google.common.base.Objects;

public class ShiroDbRealm extends AuthorizingRealm {

	protected AccountService accountService;

	/**
	 * 认证回调函数,登录时调用.  
	 * 
	 * 之前 HostAuthenticationToken  
	 * authcBasic 的认证方式
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authcToken) throws AuthenticationException {
		//UsernamePasswordToken to = new UsernamePasswordToken("username", "password");
		//to.setRememberMe(true);
		//Subject currentUser = SecurityUtils.getSubject();
		//currentUser.login(to);		
		System.out.println("ShiroDbRealm ---->  doGetAuthenticationInfo authcToken");
		UsernamePasswordToken token = (UsernamePasswordToken) authcToken;
		//UsernamePasswordToken token = (UsernamePasswordToken) to;
		System.out.println("token.getCredentials()："+token.getCredentials());
		System.out.println("token.getHost()："+token.getHost());
		System.out.println("token.getUsername()："+token.getUsername());
		System.out.println("token.getPassword()："+String.valueOf(token.getPassword()));
		System.out.println("token.getPrincipal()："+token.getPrincipal());		
		User user = accountService.findUserByLoginName(token.getUsername());
		if (user != null) {
			byte[] salt = Encodes.decodeHex(user.getSalt());
			return new SimpleAuthenticationInfo(new ShiroUser(user.getId(), user.getLoginName(), user.getName()),
					user.getPassword(), ByteSource.Util.bytes(salt), getName());
		} else {
			return null;
		}	
	}
	
	/**
	 * 认证回调函数,登录时调用. new  rest
	 * 
	 * rest 的认证方式
	 * 
	 * 新加的方式  未测试
	 * 
	 * 参照   第二十章 无状态Web应用集成——《跟我学Shiro》
	 * http://jinnianshilongnian.iteye.com/blog/2041909
	 */
	//@Override
	protected AuthenticationInfo doGetAuthenticationInfo_new (AuthenticationToken authcToken) throws AuthenticationException {		
		System.out.println("ShiroDbRealm ---->  doGetAuthenticationInfo authcToken");
		StatelessToken statelessToken = (StatelessToken) authcToken;
        String username = statelessToken.getUsername();
        String key = getKey(username);//根据用户名获取密钥（和客户端的一样）
        //在服务器端生成客户端参数消息摘要
        String serverDigest = HmacSHA256Utils.digest(key, statelessToken.getParams());
        System.out.println("statelessToken.getClientDigest():"+statelessToken.getClientDigest());
        System.out.println("serverDigest:"+serverDigest);
        
        User user = accountService.findUserByLoginName(username);
		if (user != null) {
			byte[] salt = Encodes.decodeHex(user.getSalt());
			return new SimpleAuthenticationInfo(new ShiroUser(user.getId(), user.getLoginName(), user.getName()),
					user.getPassword(), ByteSource.Util.bytes(salt), getName());
		} else {
			return null;
		}   
        
        //然后进行客户端消息摘要和服务器端消息摘要的匹配
        //return new SimpleAuthenticationInfo(
        //        username,
        //        serverDigest,
        //        getName());		
	}
	
	
    private String getKey(String username) {//得到密钥，此处硬编码一个
        if("admin".equals(username)) {
            return "dadadswdewq2ewdwqdwadsadasd";
        }
        return null;
    }
	
	
	
	/**
	 * 授权查询回调函数, 进行鉴权但缓存中无用户的授权信息时调用.
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		System.out.println("ShiroDbRealm ---->  doGetAuthorizationInfo principals");
		ShiroUser shiroUser = (ShiroUser) principals.getPrimaryPrincipal();
		User user = accountService.findUserByLoginName(shiroUser.loginName);
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRoles(user.getRoleList());
		return info;
	}

	/**
	 * 设定Password校验的Hash算法与迭代次数.
	 */
	@PostConstruct
	public void initCredentialsMatcher() {
		HashedCredentialsMatcher matcher = new HashedCredentialsMatcher(AccountService.HASH_ALGORITHM);
		matcher.setHashIterations(AccountService.HASH_INTERATIONS);

		setCredentialsMatcher(matcher);
	}

	public void setAccountService(AccountService accountService) {
		this.accountService = accountService;
	}

	/**
	 * 自定义Authentication对象，使得Subject除了携带用户的登录名外还可以携带更多信息.
	 */
	public static class ShiroUser implements Serializable {


		private static final long serialVersionUID = -1373760761780840081L;
		public Long id;
		public String loginName;
		public String name;

		public ShiroUser(Long id, String loginName, String name) {
			System.out.println(id+" "+loginName+" "+name );
			this.id = id;
			this.loginName = loginName;
			this.name = name;
		}

		public String getName() {
			return name;
		}

		/**
		 * 本函数输出将作为默认的<shiro:principal/>输出.
		 */
		@Override
		public String toString() {
			return loginName;
		}

		/**
		 * 重载hashCode,只计算loginName;
		 */
		@Override
		public int hashCode() {
			return Objects.hashCode(loginName);
		}

		/**
		 * 重载equals,只计算loginName;
		 */
		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			ShiroUser other = (ShiroUser) obj;
			if (loginName == null) {
				if (other.loginName != null) {
					return false;
				}
			} else if (!loginName.equals(other.loginName)) {
				return false;
			}
			return true;
		}
	}
}
