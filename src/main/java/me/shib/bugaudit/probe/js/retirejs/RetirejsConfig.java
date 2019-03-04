package me.shib.bugaudit.probe.js.retirejs;

import me.shib.bugaudit.probe.ProbeConfig;

import java.util.HashMap;
import java.util.Map;

public class RetirejsConfig extends ProbeConfig {

    private Map<String, Integer> priorityMap;

    RetirejsConfig() {
        this.priorityMap = new HashMap<>();
    }

    @Override
    protected Map<String, Integer> getDefaultPriorityMap() {
        return this.priorityMap;
    }
}
