package gov.gsa.pivconformance.gui;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Selects and packages evidence for exactly one completed CCT run. */
public class ReviewPackageBuilder {
	private static final DateTimeFormatter PACKAGE_TIME = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
	private static final long DETERMINISTIC_ZIP_TIME = 315532800000L; // 1980-01-01, valid in ZIP files
	private static final String[] RUN_DIRECTORIES = { "logs", "piv-artifacts", "x509-artifacts" };
	private final Clock m_clock;

	public ReviewPackageBuilder() {
		this(Clock.systemDefaultZone());
	}

	ReviewPackageBuilder(Clock clock) {
		m_clock = clock;
	}

	public ReviewPackage build(CompletedTestRun run) throws IOException {
		if (run == null) throw new IllegalStateException("No completed test run is available to package");
		Path resultsDirectory = requireDirectory(run.getResultsDirectory(), "Results directory");
		Path database = requireRegularFile(run.getDatabasePath(), "Selected test database");
		Path conformanceCsv = requireRegularFile(run.getConformanceCsv(), "Conformance CSV");
		Path discoveredCsv = findConformanceCsv(resultsDirectory, run.getTimeStampPrefix());
		if (!Files.isSameFile(conformanceCsv, discoveredCsv)) {
			throw new IOException("The completed run's conformance CSV no longer matches its recorded result");
		}
		List<SourceEntry> entries = new ArrayList<>();
		String prefix = run.getTimeStampPrefix() + "-";

		for (String directoryName : RUN_DIRECTORIES) {
			Path directory = resultsDirectory.resolve(directoryName);
			if ("logs".equals(directoryName) && !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
				throw new IOException("The completed run's logs directory is unavailable: " + directory);
			}
			if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
				collectRunFiles(resultsDirectory, directory, prefix, entries);
			}
		}

		long csvCount = entries.stream()
				.filter(entry -> entry.name.startsWith("logs/") && entry.name.toLowerCase().endsWith(".csv"))
				.count();
		if (csvCount != 1) {
			throw new IOException("Expected exactly one conformance CSV for completed run "
					+ run.getTimeStampPrefix() + ", but found " + csvCount);
		}

		Path trustDirectory = requireDirectory(resultsDirectory.resolve("x509-certs"), "Trust-path directory");
		int entriesBeforeTrustPath = entries.size();
		collectAllFiles(resultsDirectory, trustDirectory, entries);
		if (entries.size() == entriesBeforeTrustPath) {
			throw new IOException("The trust-path directory contains no files: " + trustDirectory);
		}
		entries.add(new SourceEntry(database, database.getFileName().toString()));
		validateEntries(entries);

		Collections.sort(entries, Comparator.comparing(entry -> entry.name));
		Path target = uniqueTarget(resultsDirectory);
		Path temporary = Files.createTempFile(resultsDirectory, ".cct-review-results-", ".tmp");
		long size;
		String sha256;
		try {
			writeZip(temporary, entries);
			size = Files.size(temporary);
			sha256 = sha256(temporary);
			moveIntoPlace(temporary, target);
		} finally {
			Files.deleteIfExists(temporary);
		}
		return new ReviewPackage(target, size, sha256);
	}

	public static Path findConformanceCsv(Path resultsDirectory, String timeStampPrefix) throws IOException {
		if (timeStampPrefix == null || timeStampPrefix.trim().isEmpty()) {
			throw new IOException("The completed run has no timestamp prefix");
		}
		Path logs = resultsDirectory.toAbsolutePath().normalize().resolve("logs");
		if (!Files.isDirectory(logs, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("Results logs directory is unavailable: " + logs);
		}
		List<Path> matches = new ArrayList<>();
		try (Stream<Path> paths = Files.walk(logs)) {
			Iterator<Path> iterator = paths.iterator();
			while (iterator.hasNext()) {
				Path path = iterator.next();
				if (Files.isSymbolicLink(path)) {
					if (path.getFileName().toString().startsWith(timeStampPrefix + "-")) {
						throw new IOException("Run evidence may not be a symbolic link: " + path);
					}
					continue;
				}
				if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
						&& path.getFileName().toString().startsWith(timeStampPrefix + "-")
						&& path.getFileName().toString().toLowerCase().endsWith(".csv")) {
					matches.add(path.toAbsolutePath().normalize());
				}
			}
		}
		if (matches.size() != 1) {
			throw new IOException("Expected exactly one conformance CSV for the completed run, but found " + matches.size());
		}
		return matches.get(0);
	}

	private void collectRunFiles(Path base, Path directory, String prefix, List<SourceEntry> entries) throws IOException {
		try (Stream<Path> paths = Files.walk(directory)) {
			Iterator<Path> iterator = paths.iterator();
			while (iterator.hasNext()) {
				Path path = iterator.next();
				if (Files.isSymbolicLink(path)) {
					if (path.getFileName().toString().startsWith(prefix)) {
						throw new IOException("Run evidence may not be a symbolic link: " + path);
					}
					continue;
				}
				if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
						&& path.getFileName().toString().startsWith(prefix)) {
					entries.add(new SourceEntry(path, entryName(base, path)));
				}
			}
		}
	}

	private void collectAllFiles(Path base, Path directory, List<SourceEntry> entries) throws IOException {
		try (Stream<Path> paths = Files.walk(directory)) {
			Iterator<Path> iterator = paths.iterator();
			while (iterator.hasNext()) {
				Path path = iterator.next();
				if (Files.isSymbolicLink(path)) {
					throw new IOException("Trust-path material may not be a symbolic link: " + path);
				}
				if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
					entries.add(new SourceEntry(path, entryName(base, path)));
				}
			}
		}
	}

	private static Path requireDirectory(Path path, String description) throws IOException {
		Path normalized = path.toAbsolutePath().normalize();
		if (Files.isSymbolicLink(normalized) || !Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException(description + " is unavailable: " + normalized);
		}
		return normalized;
	}

	private static Path requireRegularFile(Path path, String description) throws IOException {
		Path normalized = path.toAbsolutePath().normalize();
		if (Files.isSymbolicLink(normalized) || !Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)
				|| !Files.isReadable(normalized)) {
			throw new IOException(description + " is unavailable: " + normalized);
		}
		return normalized;
	}

	private static String entryName(Path base, Path file) throws IOException {
		Path normalizedBase = base.toAbsolutePath().normalize();
		Path normalizedFile = file.toAbsolutePath().normalize();
		if (!normalizedFile.startsWith(normalizedBase)) {
			throw new IOException("Package input is outside the results directory: " + file);
		}
		return normalizedBase.relativize(normalizedFile).toString().replace('\\', '/');
	}

	private static void validateEntries(List<SourceEntry> entries) throws IOException {
		Set<String> names = new HashSet<>();
		for (SourceEntry entry : entries) {
			Path normalized = Path.of(entry.name).normalize();
			if (normalized.isAbsolute() || entry.name.startsWith("../") || entry.name.contains("/../")
					|| !names.add(entry.name)) {
				throw new IOException("Unsafe or duplicate ZIP entry: " + entry.name);
			}
		}
	}

	private Path uniqueTarget(Path directory) {
		String baseName = "cct-review-results-" + PACKAGE_TIME.format(LocalDateTime.now(m_clock));
		Path candidate = directory.resolve(baseName + ".zip");
		int suffix = 2;
		while (Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
			candidate = directory.resolve(baseName + "-" + suffix++ + ".zip");
		}
		return candidate;
	}

	private static void writeZip(Path output, List<SourceEntry> entries) throws IOException {
		try (OutputStream fileOutput = Files.newOutputStream(output, StandardOpenOption.TRUNCATE_EXISTING);
				ZipOutputStream zip = new ZipOutputStream(fileOutput)) {
			byte[] buffer = new byte[16 * 1024];
			for (SourceEntry source : entries) {
				ZipEntry entry = new ZipEntry(source.name);
				entry.setTime(DETERMINISTIC_ZIP_TIME);
				zip.putNextEntry(entry);
				try (InputStream input = new BufferedInputStream(Files.newInputStream(source.path))) {
					int read;
					while ((read = input.read(buffer)) >= 0) {
						if (read > 0) zip.write(buffer, 0, read);
					}
				}
				zip.closeEntry();
			}
		}
	}

	private static void moveIntoPlace(Path source, Path target) throws IOException {
		try {
			Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
		} catch (AtomicMoveNotSupportedException e) {
			Files.move(source, target);
		}
	}

	private static String sha256(Path path) throws IOException {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			try (InputStream input = new BufferedInputStream(Files.newInputStream(path))) {
				byte[] buffer = new byte[16 * 1024];
				int read;
				while ((read = input.read(buffer)) >= 0) {
					if (read > 0) digest.update(buffer, 0, read);
				}
			}
			StringBuilder result = new StringBuilder();
			for (byte value : digest.digest()) result.append(String.format("%02x", value & 0xff));
			return result.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("SHA-256 is unavailable", e);
		}
	}

	private static final class SourceEntry {
		private final Path path;
		private final String name;

		private SourceEntry(Path path, String name) {
			this.path = path;
			this.name = name;
		}
	}
}
