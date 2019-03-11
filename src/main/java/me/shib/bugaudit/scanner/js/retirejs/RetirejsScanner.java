package me.shib.bugaudit.scanner.js.retirejs;

import me.shib.bugaudit.commons.BugAuditContent;
import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class RetirejsScanner extends BugAuditScanner {

    private static final transient Lang lang = Lang.JavaScript;
    private static final transient String tool = "RetireJS";
    private static final transient String resultFilePath = "retirejs-output.json";

    public RetirejsScanner() {
        this.getBugAuditScanResult().addKey("Vulnerable-Dependency");
    }

    private static int getPriorityForSeverity(String severity) {
        switch (severity) {
            case "high":
                return 2;
            case "medium":
                return 3;
            case "low":
                return 4;
            case "urgent":
                return 1;
            case "critical":
                return 1;
            default:
                return 3;
        }
    }

    private void retirejsExecutor(String command) throws BugAuditException {
        CommandExecutor commandExecutor = new CommandExecutor();
        commandExecutor.enableConsoleOutput(true);
        commandExecutor.runCommand(command);
        String response = commandExecutor.getConsoleOutput();
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new BugAuditException("Install npm before proceeding");
        }
    }

    private void installRetireJS() throws BugAuditException {
        System.out.println("Installing RetireJS...");
        retirejsExecutor("npm install -g retirejs");
    }

    private void buildProject() throws BugAuditException {
        System.out.println("Building Project...");
        retirejsExecutor("npm install");
    }

    private void runRetireJS() throws BugAuditException {
        System.out.println("Running RetireJS...");
        retirejsExecutor("retire -p --outputformat json --outputpath " + resultFilePath);
    }

    private void parseResultData(File file) throws IOException {
        RetirejsResult retirejsResult = RetirejsResult.getResult(file);
        if (retirejsResult.getData() != null) {
            for (RetirejsResult.Data data : retirejsResult.getData()) {
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
                                Bug bug = getBugAuditScanResult()
                                        .newBug(title.toString(), getPriorityForSeverity(vulnerability.getSeverity()));
                                StringBuilder description = new StringBuilder();
                                description.append("A known vulnerability in **")
                                        .append(result.getComponent()).append("** exists in ").append("**[")
                                        .append(getBugAuditScanResult().getRepo()).append("](")
                                        .append(getBugAuditScanResult().getRepo().getUrl()).append(")**.\n");
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
    protected BugAuditScannerConfig getDefaultScannerConfig() {
        return new RetirejsConfig();
    }

    @Override
    protected Lang getLang() {
        return lang;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public void scan() throws BugAuditException, IOException {
        File resultFile = new File(resultFilePath);
        if (!isParserOnly()) {
            resultFile.delete();
            installRetireJS();
            buildProject();
            runRetireJS();
        }
        parseResultData(resultFile);
    }
}
