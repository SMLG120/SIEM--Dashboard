package com.enterprise.siem.detection;

public interface RuleChangePublisher {
    void publish(RuleChange change);
}