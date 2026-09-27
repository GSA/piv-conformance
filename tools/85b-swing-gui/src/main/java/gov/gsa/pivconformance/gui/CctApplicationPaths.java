package gov.gsa.pivconformance.gui;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Resolves installed resources separately from writable CCT run data. */
final class CctApplicationPaths {
	static final String DATA_DIRECTORY_PROPERTY = "cct.data.dir";
	static final String RESOURCE_DIRECTORY_PROPERTY = "cct.resource.dir";
	private static final String PACKAGED_PROPERTY = "cct.packaged";
	private static final String[] REVIEW_RESOURCES = {
			"pdval.properties",
			"x509-certs/cacerts.jks",
			"x509-certs/valid/policy.xml",
			"x509-certs/valid/valid.zip"
	};

	private static Path s_dataDirectory;
	private static Path s_resourceDirectory;

	private CctApplicationPaths() {
	}

	static synchronized void initialize() {
		if (s_dataDirectory != null) return;

		s_resourceDirectory = configuredDirectory(RESOURCE_DIRECTORY_PROPERTY);
		if (s_resourceDirectory == null) {
			s_resourceDirectory = Boolean.getBoolean(PACKAGED_PROPERTY)
					? packagedResourceDirectory()
					: workingDirectory();
		}

		s_dataDirectory = configuredDirectory(DATA_DIRECTORY_PROPERTY);
		if (s_dataDirectory == null) {
			s_dataDirectory = Boolean.getBoolean(PACKAGED_PROPERTY)
					? windowsDataDirectory()
					: workingDirectory();
		}

		try {
			Files.createDirectories(s_dataDirectory);
			System.setProperty(DATA_DIRECTORY_PROPERTY, s_dataDirectory.toString());
			System.setProperty(RESOURCE_DIRECTORY_PROPERTY, s_resourceDirectory.toString());
			if (Boolean.getBoolean(PACKAGED_PROPERTY)) copyReviewResources();
		} catch (IOException e) {
			throw new IllegalStateException("Unable to prepare the writable CCT data directory "
					+ s_dataDirectory, e);
		}
	}

	static Path dataDirectory() {
		initialize();
		return s_dataDirectory;
	}

	static Path resourceDirectory() {
		initialize();
		return s_resourceDirectory;
	}

	static Path findResource(String relativeName) {
		initialize();
		Path workingCopy = workingDirectory().resolve(relativeName).normalize();
		if (Files.isReadable(workingCopy)) return workingCopy;

		Path installedCopy = s_resourceDirectory.resolve(relativeName).normalize();
		if (installedCopy.startsWith(s_resourceDirectory) && Files.isReadable(installedCopy)) {
			return installedCopy;
		}
		return null;
	}

	static Path requireResource(String relativeName) {
		Path resource = findResource(relativeName);
		if (resource == null) throw new IllegalStateException("Required CCT resource is missing: " + relativeName);
		return resource;
	}

	private static Path configuredDirectory(String propertyName) {
		String configured = System.getProperty(propertyName);
		return configured == null || configured.isBlank()
				? null
				: Path.of(configured).toAbsolutePath().normalize();
	}

	private static Path workingDirectory() {
		return Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
	}

	private static Path packagedResourceDirectory() {
		try {
			Path codeLocation = Path.of(GuiRunnerApplication.class.getProtectionDomain()
					.getCodeSource().getLocation().toURI()).toAbsolutePath().normalize();
			Path parent = Files.isRegularFile(codeLocation) ? codeLocation.getParent() : codeLocation;
			if (parent != null && Files.isDirectory(parent)) return parent;
			throw new IllegalStateException("CCT application resource directory is unavailable");
		} catch (URISyntaxException e) {
			throw new IllegalStateException("Unable to resolve the CCT application resource directory", e);
		}
	}

	private static Path windowsDataDirectory() {
		String localAppData = System.getenv("LOCALAPPDATA");
		Path base = localAppData == null || localAppData.isBlank()
				? Path.of(System.getProperty("user.home"), "AppData", "Local")
				: Path.of(localAppData);
		return base.resolve("GSA").resolve("CCT").toAbsolutePath().normalize();
	}

	private static void copyReviewResources() throws IOException {
		for (String relativeName : REVIEW_RESOURCES) {
			Path source = s_resourceDirectory.resolve(relativeName).normalize();
			if (!source.startsWith(s_resourceDirectory) || !Files.isRegularFile(source)) {
				throw new IOException("Packaged CCT resource is missing: " + source);
			}
			Path target = s_dataDirectory.resolve(relativeName).normalize();
			if (!target.startsWith(s_dataDirectory)) {
				throw new IOException("Invalid CCT data path: " + target);
			}
			Files.createDirectories(target.getParent());
			if (!Files.exists(target)) Files.copy(source, target, StandardCopyOption.COPY_ATTRIBUTES);
		}
	}
}
