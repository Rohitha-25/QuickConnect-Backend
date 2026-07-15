package com.ust.qcb.dto;

public class AIChatResponse {
    private String reply;
    private String recommendedService; // nullable — set only when AI identifies a clear match

    public AIChatResponse() {}

    public AIChatResponse(String reply, String recommendedService) {
        this.reply = reply;
        this.recommendedService = recommendedService;
    }

    public String getReply() { return reply; }
    public void setReply(String reply) { this.reply = reply; }

    public String getRecommendedService() { return recommendedService; }
    public void setRecommendedService(String recommendedService) { this.recommendedService = recommendedService; }
}
