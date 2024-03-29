package me.shib.bugaudit.scanner.js.retirejs;

import me.shib.bugaudit.commons.BugAuditContent;
import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.Bug;
import me.shib.bugaudit.scanner.BugAuditScanner;
import me.shib.bugaudit.scanner.Lang;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class RetirejsScanner extends BugAuditScanner {

    private static final transient String tool = "RetireJS";
    private static final transient File retireJsResultFile = new File("bugaudit-retirejs-result.json");

    public RetirejsScanner() throws BugAuditException {
        super();
        this.getBugAuditScanResult().addKey("Vulnerable-Dependency");
    }

    private static int getPriorityForSeverity(String severity) {
        switch (severity) {
            case "high":
            case "critical":
            case "urgent":
                return 2;
            case "low":
                return 4;
            default:
                return 3;
        }
    }

    private void retirejsExecutor(String command) throws BugAuditException, IOException, InterruptedException {
        String response = runCommand(command);
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new BugAuditException("Install npm before proceeding");
        }
    }

    private void npmProjectBuild() throws BugAuditException, IOException, InterruptedException {
        System.out.println("Building Project...");
        retirejsExecutor("npm install");
    }

    private void runRetireJS() throws BugAuditException, IOException, InterruptedException {
        System.out.println("Running RetireJS...");
        retirejsExecutor("retire -p --outputformat json --outputpath " + retireJsResultFile.getAbsolutePath());
    }

    private void parseResultData(File file) throws IOException, BugAuditException {
        List<RetirejsResult.Data> dataList = RetirejsResult.getResult(file);
        if (dataList != null) {
            for (RetirejsResult.Data data : dataList) {
                if (data.getResults() != null) {
                    for (RetirejsResult.Data.Result result : data.getResults()) {
                        if (result.getVulnerabilities() != null) {
                            for (RetirejsResult.Data.Result.Vulnerability vulnerability : result.getVulnerabilities()) {
                                StringBuilder title = new StringBuilder();
                                if (vulnerability.getBelow() != null) {
                                    title.append("Vulnerability found in ").append(result.getComponent())
                                            .append(" (Below ").append(vulnerability.getBelow()).append(") of ")
                                            .append(getBugAuditScanResult().getRepo());
                                } else if (vulnerability.getAtOrAbove() != null) {
                                    title.append("Vulnerability found in ").append(result.getComponent())
                                            .append(" (At/Above ").append(vulnerability.getAtOrAbove())
                                            .append(") of ").append(getBugAuditScanResult().getRepo());
                                } else {
                                    title.append("Vulnerability found in ").append(result.getComponent())
                                            .append(" of ").append(getBugAuditScanResult().getRepo());
                                }
                                Bug bug = new Bug(title.toString(), getPriorityForSeverity(vulnerability.getSeverity()));
                                StringBuilder description = new StringBuilder();
                                description.append("A known vulnerability in **")
                                        .append(result.getComponent()).append("** exists in ").append("**[")
                                        .append(getBugAuditScanResult().getRepo()).append("](")
                                        .append(getBugAuditScanResult().getRepo().getWebUrl()).append(")**.\n");
                                description.append(" * **Build File Path:** ").append(data.getFile()).append("\n");
                                description.append(" * **Component:** ").append(result.getComponent()).append("\n");
                                description.append(" * **Version:** ").append(result.getVersion()).append("\n");
                                if (vulnerability.getAtOrAbove() != null) {
                                    description.append(" * **Severity:** ").append(vulnerability.getSeverity()).append("\n");
                                }
                                if (vulnerability.getBelow() != null) {
                                    bug.addKey("Below-" + vulnerability.getBelow());
                                    description.append(" * **Below:** ").append(vulnerability.getBelow()).append("\n");
                                }
                                if (vulnerability.getAtOrAbove() != null) {
                                    bug.addKey("AtOrAbove-" + vulnerability.getAtOrAbove());
                                    description.append(" * **At (or) Above:** ").append(vulnerability.getAtOrAbove()).append("\n");
                                }
                                List<String> ignorableInfo = new ArrayList<>();
                                if (vulnerability.getIdentifiers() != null) {
                                    if (vulnerability.getIdentifiers().getIssue() != null) {
                                        bug.addKey("JS-Issue-" + vulnerability.getIdentifiers().getIssue());
                                        String issueURL = null;
                                        for (String info : vulnerability.getInfo()) {
                                            if (info.contains(vulnerability.getIdentifiers().getIssue()) && info.toLowerCase().startsWith("http")) {
                                                issueURL = info;
                                                ignorableInfo.add(issueURL);
                                            }
                                        }
                                        description.append(" * **Issue Reference:** ");
                                        if (null == issueURL) {
                                            description.append(vulnerability.getIdentifiers().getIssue());
                                        } else {
                                            description.append("[").append(vulnerability.getIdentifiers().getIssue()).append("](")
                                                    .append(issueURL).append(")");
                                        }
                                        description.append("\n");
                                    }
                                    if (vulnerability.getIdentifiers().getBug() != null) {
                                        bug.addKey("JS-Bug-" + vulnerability.getIdentifiers().getBug());
                                        String bugURL = null;
                                        for (String info : vulnerability.getInfo()) {
                                            if (info.contains(vulnerability.getIdentifiers().getBug()) && info.toLowerCase().startsWith("http")) {
                                                bugURL = info;
                                                ignorableInfo.add(bugURL);
                                            }
                                        }
                                        description.append(" * **Bug Reference:** ");
                                        if (null == bugURL) {
                                            description.append(vulnerability.getIdentifiers().getBug());
                                        } else {
                                            description.append("[").append(vulnerability.getIdentifiers().getBug()).append("](")
                                                    .append(bugURL).append(")");
                                        }
                                        description.append("\n");
                                    }
                                    if (vulnerability.getIdentifiers().getCVE() != null
                                            && vulnerability.getIdentifiers().getCVE().size() > 0) {
                                        description.append(" * **CVE:**");
                                        for (String cve : vulnerability.getIdentifiers().getCVE()) {
                                            bug.addKey(cve);
                                            try {
                                                description.append(" ").append("[").append(cve).append("](").append(getUrlForCVE(cve)).append(")");
                                            } catch (BugAuditException e) {
                                                description.append(" ").append(cve);
                                            }
                                        }
                                        description.append("\n");
                                    }
                                }
                                Set<String> filteredReferences = new HashSet<>(vulnerability.getInfo());
                                for (String ignoreableRef : ignorableInfo) {
                                    filteredReferences.remove(ignoreableRef);
                                }
                                if (filteredReferences.size() > 0) {
                                    description.append("\n**More references:**\n");
                                    for (String filteredRef : filteredReferences) {
                                        if (filteredRef.toLowerCase().startsWith("http")) {
                                            description.append(" * [").append(filteredRef).append("](").append(filteredRef).append(")\n");
                                        } else {
                                            description.append(" * ").append(filteredRef).append("\n");
                                        }
                                    }
                                }
                                bug.setDescription(new BugAuditContent(description.toString()));
                                bug.addKey(data.getFile());
                                bug.addKey(result.getComponent());
                                bug.addKey(result.getComponent() + "-" + result.getVersion());
                                getBugAuditScanResult().addBug(bug);
                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    protected boolean isLangSupported(Lang lang) {
        return lang == Lang.JavaScript;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public void scan() throws BugAuditException, IOException, InterruptedException {
        if (!isParserOnly()) {
            retireJsResultFile.delete();
            npmProjectBuild();
            runRetireJS();
        }
        parseResultData(retireJsResultFile);
    }
}
