package com.enterprise.siem.detection;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/rules")
public class RuleController {
    private final DetectionRuleRepository ruleRepository;

    public RuleController(DetectionRuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    @GetMapping
    public List<DetectionRule> listRules() {
        return ruleRepository.all();
    }

    @GetMapping("/{id}")
    public DetectionRule ruleById(@PathVariable String id) {
        return ruleRepository.byId(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Rule not found: " + id));
    }
}