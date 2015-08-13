package com.job.lr.filter;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.AccessControlFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>User: liuy
 * <p>Date: 15-8-26
 * <p>Version: 1.0
 */
public class StatelessAuthcFilter extends AccessControlFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
    	System.out.println("in StatelessAuthcFilter 的isAccessAllowed()");
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
    	System.out.println("in StatelessAuthcFilter 的 onAccessDenied()");
        //1、客户端生成的消息摘要
        String clientDigest = request.getParameter(Constants.PARAM_DIGEST);
        System.out.println("clientDigest:"+clientDigest);
        //2、客户端传入的用户身份
        String username = request.getParameter(Constants.PARAM_USERNAME);
        System.out.println("username:"+username);
        //3、客户端请求的参数列表
        Map<String, String[]> params = new HashMap<String, String[]>(request.getParameterMap());
        params.remove(Constants.PARAM_DIGEST);

        //4、生成无状态Token
        //StatelessToken token = new StatelessToken(username, params, clientDigest);
        //change org.apache.shiro.web.filter.authc.AuthenticatingFilter  liuy add
        //AuthenticationToken token = createToken(request, response);
        AuthenticationToken token = new UsernamePasswordToken(username, "admin", true, "127.0.0.2" );
        
        System.out.println("here ok");
        try {
            //5、委托给Realm进行登录
        	SecurityUtils.getSubject().login(token);
        	//getSubject(request, response).login(token);
        } catch (Exception e) {
            e.printStackTrace();
            onLoginFail(response); //6、登录失败
            return false;
        }
        return true;
    }
    
    


    
    
    

    //登录失败时默认返回401状态码
    private void onLoginFail(ServletResponse response) throws IOException {
    	System.out.println("in StatelessAuthcFilter 的 onLoginFail()");
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.getWriter().write("login error");
    }
}