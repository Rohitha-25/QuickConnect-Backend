package com.ust.qcb.dto;

public class AuthenticationResponse {
	private String token;
    private String message;
    // ✅ FIX: Added userId so frontend can use it for booking/review endpoints
    private Long userId;

    public AuthenticationResponse() {
    }

    public AuthenticationResponse(String token, String message) {
        this.token = token;
        this.message = message;
    }

    // ✅ FIX: New constructor that also accepts userId
    public AuthenticationResponse(String token, String message, Long userId) {
        this.token = token;
        this.message = message;
        this.userId = userId;
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
}
