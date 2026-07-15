package com.ust.qcb.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ust.qcb.dto.AIChatRequest;
import com.ust.qcb.dto.AIChatResponse;
import com.ust.qcb.service.AIService;

@RestController
@RequestMapping("/api/ai")
public class AIController {

    @Autowired
    private AIService aiService;

    @PostMapping("/chat")
    public AIChatResponse chat(@RequestBody AIChatRequest request) {
        return aiService.chat(request);
    }
}
