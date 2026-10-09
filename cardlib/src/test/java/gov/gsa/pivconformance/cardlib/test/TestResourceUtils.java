package gov.gsa.pivconformance.cardlib.test;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

final class TestResourceUtils {
    private TestResourceUtils() {
    }

    /**
     * Resolves Gradle's exploded test-resource output. Parser APIs currently
     * require a Path, so packaged/JAR-backed test resources are intentionally
     * rejected rather than copied or given different semantics.
     */
    static Path path(String resourceName) {
        URL resource = TestResourceUtils.class.getClassLoader().getResource(resourceName);
        if (resource == null) {
            throw new IllegalArgumentException("Missing test resource: " + resourceName);
        }
        if (!"file".equals(resource.getProtocol())) {
            throw new IllegalArgumentException("Test resource is not file-backed: " + resourceName);
        }
        try {
            URI resourceUri = resource.toURI();
            return Paths.get(resourceUri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid test resource URI: " + resourceName, e);
        }
    }
}
