package net.izelon.spring_jwt.entrypoints;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class JwtAuthEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        final Map<String, Object> mapper = new HashMap<>();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        mapper.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        mapper.put("error", "Unauthorized");
        mapper.put("message", authException.getMessage());
        mapper.put("path", request.getServletPath());

        final ObjectMapper om = new ObjectMapper();
        om.writeValue(response.getOutputStream(), mapper);

    }

}
