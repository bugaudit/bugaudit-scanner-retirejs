package me.shib.bugaudit.scanner.js.retirejs;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.List;

final class RetirejsData {


    private static final transient String currentPath = System.getProperty("user.dir") + "/";

    private static final Gson gson = new GsonBuilder().create();
    private String file;
    private List<Result> results;

    private static String replaceLast(String content, String toReplace, String replacement) {
        int start = content.lastIndexOf(toReplace);
        return content.substring(0, start) +
                replacement +
                content.substring(start + toReplace.length());
    }

    private static void cleanUpFilePath(RetirejsData data) {
        data.setFile(data.getFile().replaceFirst(currentPath, ""));
        if (data.getFile().endsWith(".min.js")) {
            data.setFile(replaceLast(data.getFile(), ".min.js", ".js"));
        }
    }

    static synchronized List<RetirejsData> getDataList(File jsonFile) throws IOException {
        StringBuilder jsonContent = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(jsonFile));
        String line;
        while ((line = br.readLine()) != null) {
            jsonContent.append(line).append("\n");
        }
        br.close();
        Type type = new TypeToken<List<RetirejsData>>() {
        }.getType();
        List<RetirejsData> dataList = gson.fromJson(jsonContent.toString(), type);
        for (RetirejsData data : dataList) {
            cleanUpFilePath(data);
        }
        return dataList;
    }

    String getFile() {
        return file;
    }

    void setFile(String file) {
        this.file = file;
    }

    List<Result> getResults() {
        return results;
    }

    final class Result {
        private String version;
        private String component;
        private String detection;
        private List<Result.Vulnerability> vulnerabilities;

        String getVersion() {
            return version;
        }

        String getComponent() {
            return component;
        }

        String getDetection() {
            return detection;
        }

        List<Result.Vulnerability> getVulnerabilities() {
            return vulnerabilities;
        }

        final class Vulnerability {

            private List<String> info;
            private String below;
            private String atOrAbove;
            private String severity;
            private Result.Vulnerability.Identifiers identifiers;

            List<String> getInfo() {
                return info;
            }

            String getBelow() {
                return below;
            }

            public String getAtOrAbove() {
                return atOrAbove;
            }

            String getSeverity() {
                return severity;
            }

            Result.Vulnerability.Identifiers getIdentifiers() {
                return identifiers;
            }

            final class Identifiers {

                private String issue;
                private String bug;
                private String summary;
                private List<String> CVE;

                String getIssue() {
                    return issue;
                }

                String getBug() {
                    return bug;
                }

                String getSummary() {
                    return summary;
                }

                List<String> getCVE() {
                    return CVE;
                }
            }
        }
    }

}
