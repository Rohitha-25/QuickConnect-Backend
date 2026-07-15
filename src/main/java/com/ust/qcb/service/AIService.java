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

    @Value("${anthropic.api.key}")
    private String apiKey;

    private static final String ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
    private static final Pattern RECOMMEND_PATTERN = Pattern.compile("RECOMMEND:\\s*(.+)", Pattern.CASE_INSENSITIVE);

    public AIChatResponse chat(AIChatRequest request) {
        // ✅ Build the system prompt dynamically from REAL services in the DB —
        // this means the AI can never recommend a service that doesn't exist,
        // and automatically stays up to date if you add/remove services.
        String serviceList = serviceRepository.findAll().stream()
                .map(s -> "- " + s.getServiceName() + " (" + s.getCategory() + "): " + s.getDescription())
                .collect(Collectors.joining("\n"));

        String systemPrompt = "You are a helpful assistant for QuickConnect, a home services platform.\n"
                + "Your job is to understand what problem the user has and recommend the most appropriate "
                + "service from this exact list (never invent a service that isn't listed):\n\n"
                + serviceList + "\n\n"
                + "Respond naturally and briefly (2-3 sentences max). "
                + "If you can confidently match a service, end your reply on a new line with exactly:\n"
                + "RECOMMEND: <exact service name from the list>\n"
                + "If you cannot determine a clear match, ask one short clarifying question instead, "
                + "and do not include a RECOMMEND line.";

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set("x-api-key", apiKey);
        headers.set("anthropic-version", "2023-06-01");
        headers.setContentType(MediaType.APPLICATION_JSON);

        List<Map<String, String>> messages = new ArrayList<>();
        if (request.getHistory() != null) {
            for (AIChatRequest.AIChatMessage m : request.getHistory()) {
                if ("user".equalsIgnoreCase(m.getRole())) {
                    Map<String, String> msg = new HashMap<>();
                    msg.put("role", "user");
                    msg.put("content", m.getText());
                    messages.add(msg);
                }
            }
        }
        Map<String, String> currentMsg = new HashMap<>();
        currentMsg.put("role", "user");
        currentMsg.put("content", request.getMessage());
        messages.add(currentMsg);

        Map<String, Object> body = new HashMap<>();
        body.put("model", "claude-sonnet-4-6");
        body.put("max_tokens", 500);
        body.put("system", systemPrompt);
        body.put("messages", messages);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> response = restTemplate.postForObject(ANTHROPIC_URL, entity, Map.class);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> content = (List<Map<String, Object>>) response.get("content");
            String fullText = content.isEmpty() ? "" : (String) content.get(0).get("text");

            Matcher matcher = RECOMMEND_PATTERN.matcher(fullText);
            String recommended = null;
            String displayText = fullText;

            if (matcher.find()) {
                recommended = matcher.group(1).trim();
                displayText = fullText.replaceAll("RECOMMEND:\\s*.+", "").trim();
            }

            return new AIChatResponse(displayText, recommended);

        } catch (Exception e) {
            return new AIChatResponse(
                "Sorry, I'm having trouble right now. Please browse our services directly or try again shortly.",
                null
            );
        }
    }
}
