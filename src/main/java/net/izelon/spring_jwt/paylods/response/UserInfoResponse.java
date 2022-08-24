package net.izelon.spring_jwt.paylods.response;

import java.util.List;

public class UserInfoResponse {
    private String username;
    private String jwt;
    private List<String> roles;

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public UserInfoResponse(String username, String jwt, List<String> roles) {
        this.username = username;
        this.jwt = jwt;
        this.roles = roles;
    }

    public UserInfoResponse(String username, String jwt) {
        this.username = username;
        this.jwt = jwt;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

}
