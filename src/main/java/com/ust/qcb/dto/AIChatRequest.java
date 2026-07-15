package com.ust.qcb.dto;

import java.util.List;

public class AIChatRequest {
    private String message;
    private List<AIChatMessage> history;

    public AIChatRequest() {}

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public List<AIChatMessage> getHistory() { return history; }
    public void setHistory(List<AIChatMessage> history) { this.history = history; }

    public static class AIChatMessage {
        private String role;   // "user" or "ai"
        private String text;

        public AIChatMessage() {}

        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }

        public String getText() { return text; }
        public void setText(String text) { this.text = text; }
    }
}
