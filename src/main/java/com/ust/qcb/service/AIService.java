package com.ust.qcb.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.ust.qcb.dto.AIChatRequest;
import com.ust.qcb.dto.AIChatResponse;
import com.ust.qcb.repository.ServiceRepository;

@Service
public class AIService {

    @Autowired
    private ServiceRepository serviceRepository;

    @Value("${gemini.api.key}")
    private String apiKey;

    private static final String GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=";
    private static final Pattern RECOMMEND_PATTERN = Pattern.compile("RECOMMEND:\\s*(.+)", Pattern.CASE_INSENSITIVE);

    public AIChatResponse chat(AIChatRequest request) {
        String serviceList = serviceRepository.findAll().stream()
                .map(s -> "- " + s.getServiceName() + " (" + s.getCategory() + "): " + s.getDescription())
                .collect(Collectors.joining("\n"));

        String systemPrompt = "You are a helpful assistant for QuickConnect, a home services platform. "
                + "Understand the user's problem and recommend the most appropriate service from this list:\n\n"
                + serviceList + "\n\n"
                + "Respond naturally in 2-3 sentences. "
                + "If you can confidently match a service, end with:\nRECOMMEND: <exact service name>\n"
                + "If unsure, ask one clarifying question without a RECOMMEND line.";

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        List<Map<String, Object>> contents = new ArrayList<>();

        Map<String, Object> systemMsg = new HashMap<>();
        systemMsg.put("role", "user");
        systemMsg.put("parts", List.of(Map.of("text", systemPrompt)));
        contents.add(systemMsg);

        Map<String, Object> modelAck = new HashMap<>();
        modelAck.put("role", "model");
        modelAck.put("parts", List.of(Map.of("text", "Understood! I'll help users find the right service.")));
        contents.add(modelAck);

        if (request.getHistory() != null) {
            for (AIChatRequest.AIChatMessage m : request.getHistory()) {
                String role = "ai".equalsIgnoreCase(m.getRole()) ? "model" : "user";
                Map<String, Object> msg = new HashMap<>();
                msg.put("role", role);
                msg.put("parts", List.of(Map.of("text", m.getText())));
                contents.add(msg);
            }
        }

        Map<String, Object> currentMsg = new HashMap<>();
        currentMsg.put("role", "user");
        currentMsg.put("parts", List.of(Map.of("text", request.getMessage())));
        contents.add(currentMsg);

        Map<String, Object> body = new HashMap<>();
        body.put("contents", contents);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> response = restTemplate.postForObject(
                    GEMINI_URL + apiKey, entity, Map.class
            );

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> candidates = (List<Map<String, Object>>) response.get("candidates");
            @SuppressWarnings("unchecked")
            Map<String, Object> content = (Map<String, Object>) candidates.get(0).get("content");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> parts = (List<Map<String, Object>>) content.get("parts");
            String fullText = (String) parts.get(0).get("text");

            Matcher matcher = RECOMMEND_PATTERN.matcher(fullText);
            String recommended = null;
            String displayText = fullText;

            if (matcher.find()) {
                recommended = matcher.group(1).trim();
                displayText = fullText.replaceAll("RECOMMEND:\\s*.+", "").trim();
            }

            return new AIChatResponse(displayText, recommended);

        } catch (Exception e) {
            e.printStackTrace();
            return new AIChatResponse(
                    "Sorry, I'm having trouble right now. Please browse our services directly or try again shortly.",
                    null
            );
        }
    }
}
