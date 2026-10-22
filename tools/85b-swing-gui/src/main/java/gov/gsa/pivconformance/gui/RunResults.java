package gov.gsa.pivconformance.gui;

import gov.gsa.pivconformance.conformancelib.configuration.TestStatus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** Immutable run results shared by the Results tab and packaged summary. */
record RunResults(String version, Path database, Instant started, Instant finished,
                  boolean complete, List<CaseResult> cases, String executionIssue) {
    RunResults(String version, Path database, Instant started, Instant finished, boolean complete, List<CaseResult> cases) {
        this(version, database, started, finished, complete, cases, "");
    }

    RunResults {
        database = Objects.requireNonNull(database).toAbsolutePath().normalize();
        Objects.requireNonNull(started);
        Objects.requireNonNull(finished);
        cases = List.copyOf(cases);
        executionIssue = clean(executionIssue);
    }

    long passed() { return count(TestStatus.PASS); }
    long failed() { return count(TestStatus.FAIL); }
    long unsupported() { return count(TestStatus.SKIP); }
    long count(TestStatus status) { return cases.stream().filter(c -> c.status() == status).count(); }
    Duration duration() { return Duration.between(started, finished); }

    Path writeSummary(Path directory, String prefix) throws IOException {
        Files.createDirectories(directory);
        Path file = directory.resolve(prefix + "-results-summary.txt");
        StringBuilder text = new StringBuilder("CCT test results\n");
        text.append("Version: ").append(version).append("\nDatabase: ").append(database.getFileName())
                .append("\nStarted: ").append(started).append("\nFinished: ").append(finished)
                .append("\nRun: ").append(complete ? "Completed" : "Incomplete")
                .append("\nCases processed: ").append(cases.size()).append("\nPass: ").append(passed())
                .append("\nFail: ").append(failed()).append("\nUnsupported: ").append(unsupported())
                .append("\nCounts describe executed cases, not standards coverage or card certification.\n");
        if (!executionIssue.isBlank()) text.append("Execution issue: ").append(executionIssue).append("\n");
        for (CaseResult result : cases) {
            if (result.status() == TestStatus.PASS && !result.expectationMismatch()) continue;
            text.append("\n").append(result.id()).append(": ").append(result.statusText())
                    .append("\n").append(result.description()).append("\nObject: ").append(result.object())
                    .append("\nExpected: ").append(result.expectedPass() ? "Pass" : "Fail").append("\n");
            if (result.steps().isEmpty()) text.append("No assertion outcome was recorded.\n");
            for (StepResult step : result.steps()) {
                if (step.status() == TestStatus.PASS) continue;
                text.append("Step: ").append(step.method()).append("\n").append(step.reason()).append("\n");
                if (!step.expected().isBlank()) text.append("Expected value: ").append(step.expected()).append("\n");
                if (!step.actual().isBlank()) text.append("Observed value: ").append(step.actual()).append("\n");
                for (Reference ref : step.references()) {
                    text.append("Reference: ").append(ref.text()).append("\n");
                }
                if (step.references().isEmpty()) text.append("No source reference is recorded for this step.\n");
            }
            text.append("Next step: ").append(result.guidance()).append("\n");
        }
        Path temporary = Files.createTempFile(directory, ".cct-summary-", ".tmp");
        try {
            Files.writeString(temporary, text, StandardCharsets.UTF_8);
            Files.move(temporary, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temporary); }
        return file;
    }

    record Reference(String publication, String location, String url, String scope,
                     String excerpt, String documentUrl) {
        String link() { return documentUrl.isBlank() ? url : documentUrl; }
        String text() {
            return publication + ", " + location + "\n"
                    + (excerpt.isBlank() ? "" : "Official wording (excerpt):\n“" + excerpt + "”\n")
                    + "What CCT checks: " + scope + "\n" + link();
        }
    }

    record StepResult(String method, TestStatus status, boolean executionError, String reason,
                      String expected, String actual, String technical, List<Reference> references) {
        StepResult {
            method = clean(method);
            reason = clean(reason);
            expected = clean(expected);
            actual = clean(actual);
            technical = clean(technical);
            references = List.copyOf(references);
        }

        boolean booleanExpectation() {
            return (expected.equals("true") || expected.equals("false"))
                    && (actual.equals("true") || actual.equals("false"));
        }

        String explanation() {
            int suffix = reason.indexOf(" ==> expected:");
            return suffix > 0 && !expected.isBlank() && !actual.isBlank() ? reason.substring(0, suffix) : reason;
        }
    }

    record CaseResult(String id, String description, String object, boolean expectedPass,
                      TestStatus status, List<StepResult> steps) {
        CaseResult {
            id = clean(id);
            description = clean(description);
            object = friendlyObject(object);
            steps = List.copyOf(steps);
        }

        boolean expectationMismatch() {
            return status != TestStatus.SKIP && (status == TestStatus.PASS) != expectedPass;
        }

        boolean executionError() { return steps.stream().anyMatch(StepResult::executionError); }

        String statusText() {
            return switch (status) {
                case PASS -> "Pass";
                case FAIL -> "Fail";
                case SKIP -> "Unsupported";
                default -> "Not run";
            };
        }

        String reason() {
            return steps.stream().filter(s -> s.status() != TestStatus.PASS).map(StepResult::reason)
                    .distinct().collect(java.util.stream.Collectors.joining("\n\n"));
        }

        String guidance() {
            if (executionError()) return "Review this run's debug and reader logs. An execution error does not establish a card-data violation.";
            if (status == TestStatus.SKIP) {
                String lower = description.toLowerCase(Locale.ROOT);
                if (lower.contains("vendor")) return "This comparison needs the vendor's reference values; CCT has no implemented comparison for this case.";
                if (lower.contains("input images")) return "This comparison requires the two original fingerprint images. Their dimensions cannot be established from the stored card record alone.";
                if (object.equals("Key History") && reason().contains("absent optional Key History"))
                    return "The optional Key History object was unavailable. A card read alone cannot establish whether retired private keys exist.";
                return "CCT has not implemented this case's assertion or cannot establish it with the available evidence. This is not a passing result or proof of missing card data.";
            }
            if (!expectedPass) return "This profile expects a negative result. Compare the actual outcome and recorded reason with its intended negative test.";
            return "Review the recorded assertion and the matching object/debug logs for this run. Correct the specific condition before running CCT again.";
        }

        String searchText() {
            return (id + " " + description + " " + object + " " + reason()).toLowerCase(Locale.ROOT);
        }

        int attentionOrder() {
            if (executionError() || expectationMismatch()) return 0;
            if (status == TestStatus.SKIP) return 1;
            if (status == TestStatus.FAIL) return 2;
            return 3;
        }
    }

    private static String clean(String value) { return value == null ? "" : value; }

    private static String friendlyObject(String value) {
        if (value == null || value.isBlank()) return "Not specified by the selected profile";
        String name = value.replaceFirst("_OID$", "").replace('_', ' ').toLowerCase(Locale.ROOT);
        return switch (value) {
            case "CARD_CAPABILITY_CONTAINER_OID" -> "Card Capability Container";
            case "CARD_HOLDER_UNIQUE_IDENTIFIER_OID" -> "CHUID";
            case "KEY_HISTORY_OBJECT_OID" -> "Key History";
            default -> Character.toUpperCase(name.charAt(0)) + name.substring(1);
        };
    }
}
