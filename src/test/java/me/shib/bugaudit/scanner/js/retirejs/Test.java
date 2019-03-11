package me.shib.bugaudit.scanner.js.retirejs;

import java.io.File;
import java.io.IOException;

public final class Test {

    private static final String currentPath = System.getProperty("user.dir") + "/";

    private static void cleanUpFilePath(RetirejsResult.Data data) {
        data.setFile(data.getFile().replaceFirst(currentPath, ""));
    }

    public static void main(String[] args) throws IOException {
        System.out.println(currentPath);
        int count = 0;
        RetirejsResult retirejsResult = RetirejsResult.getResult(new File("test.json"));
        for (RetirejsResult.Data data : retirejsResult.getData()) {
            cleanUpFilePath(data);
            for (RetirejsResult.Data.Result result : data.getResults()) {
                for (RetirejsResult.Data.Result.Vulnerability vulnerability : result.getVulnerabilities()) {
                    if (vulnerability.getIdentifiers().getIssue() != null) {
                        System.out.print(vulnerability.getIdentifiers().getIssue() + ": ");
                        for (String info : vulnerability.getInfo()) {
                            if (info.contains(vulnerability.getIdentifiers().getIssue())) {
                                System.out.print(info);
                            }
                        }
                        System.out.println();
                    }
                    if (vulnerability.getIdentifiers().getBug() != null) {
                        System.out.print(vulnerability.getIdentifiers().getBug() + ": ");
                        for (String info : vulnerability.getInfo()) {
                            if (info.contains(vulnerability.getIdentifiers().getBug())) {
                                System.out.print(info);
                            }
                        }
                        System.out.println();
                    }
                    count++;
                }
            }
        }
        System.out.println(count);
    }

}
