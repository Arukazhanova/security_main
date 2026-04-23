package com.trendprice.securitysite.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.admin")
public class AdminProperties {

    private String username;
    private String email;
    private String password;
    private boolean createOnStartup;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isCreateOnStartup() {
        return createOnStartup;
    }

    public void setCreateOnStartup(boolean createOnStartup) {
        this.createOnStartup = createOnStartup;
    }
}