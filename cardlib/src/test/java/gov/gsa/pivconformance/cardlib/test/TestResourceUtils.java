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
     * Resolves a resource from Gradle's test output. The parsers require a file
     * path, so resources inside a JAR are not supported here.
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
