package net.izelon.spring_jwt.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import net.izelon.spring_jwt.services.UserDetailsServiceImpl;
import net.izelon.spring_jwt.utils.JwtTokenUtil;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final String BEARER = "Bearer ";
    private static final Logger logger = LoggerFactory.getLogger(JwtRequestFilter.class);

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // JWT 는 Authorization 헤더에 Bearer xxxx.yyyy.zzz 식으로 담겨올 것이다.
        final String authrozationHeader = request.getHeader("Authorization");
        if (StringUtils.startsWith(authrozationHeader, BEARER)) {
            String jwtToken = authrozationHeader.substring(BEARER.length());
            try {
                String username = jwtTokenUtil.getUsernameFromToken(jwtToken);
                if (StringUtils.isNotEmpty(username)
                        && null == SecurityContextHolder.getContext().getAuthentication()) {
                    UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);
                    if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    }
                }
            } catch (IllegalArgumentException e) {
                logger.error("Unable to fetch JWT Token: {}", e.getMessage());
            } catch (ExpiredJwtException e) {
                logger.error("JWT is expired: {}", e.getMessage());
            } catch (Exception e) {
                logger.error("ERROR : {}", e.getMessage());
            }

        } else {
            logger.error("JWT Token is not send ");
        }
        filterChain.doFilter(request, response);
    }

}
