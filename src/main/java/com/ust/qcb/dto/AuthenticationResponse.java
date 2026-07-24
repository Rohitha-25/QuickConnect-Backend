package com.ust.qcb.dto;

public class AuthenticationResponse {
	private String token;
    private String message;
    private Long userId;
    private String userName;

    public AuthenticationResponse(String token, String message, Long userId, String userName) {
        this.token = token;
        this.message = message;
        this.userId = userId;
        this.userName = userName;
    }

    public AuthenticationResponse() {
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }
}
