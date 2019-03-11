package me.shib.bugaudit.scanner.js.retirejs;

import me.shib.bugaudit.scanner.BugAuditScannerConfig;

import java.util.HashMap;
import java.util.Map;

public final class RetirejsConfig extends BugAuditScannerConfig {

    private Map<String, Integer> priorityMap;

    RetirejsConfig() {
        this.priorityMap = new HashMap<>();
    }

    @Override
    protected Map<String, Integer> getDefaultClassificationPriorityMap() {
        return this.priorityMap;
    }
}
