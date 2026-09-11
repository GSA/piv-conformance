package gov.gsa.pivconformance.gui;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Packages the files belonging to one completed CCT run. */
final class ReviewPackageBuilder {
	private static final DateTimeFormatter PACKAGE_TIME = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
	private static final String[] RUN_DIRECTORIES = { "logs", "piv-artifacts", "x509-artifacts" };

	Path build(CompletedTestRun run) throws IOException {
		if (run == null) throw new IllegalStateException("No completed test run is available to package");
		Path resultsDirectory = requireDirectory(run.getResultsDirectory(), "Results directory");
		Path database = requireFile(run.getDatabasePath(), "Selected test database");
		List<SourceEntry> entries = new ArrayList<>();
		String prefix = run.getTimeStampPrefix() + "-";

		for (String directoryName : RUN_DIRECTORIES) {
			Path directory = resultsDirectory.resolve(directoryName);
			if ("logs".equals(directoryName) && !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
				throw new IOException("The completed run's logs directory is unavailable: " + directory);
			}
			if (Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
				collectFiles(resultsDirectory, directory, prefix, entries);
			}
		}

		long csvCount = entries.stream()
				.filter(entry -> entry.name.startsWith("logs/") && entry.name.toLowerCase().endsWith(".csv"))
				.count();
		if (csvCount != 1) {
			throw new IOException("Expected exactly one conformance CSV for the completed run, but found " + csvCount);
		}

		Path trustDirectory = requireDirectory(resultsDirectory.resolve("x509-certs"), "Trust-path directory");
		int entryCount = entries.size();
		collectFiles(resultsDirectory, trustDirectory, null, entries);
		if (entries.size() == entryCount) {
			throw new IOException("The trust-path directory contains no files: " + trustDirectory);
		}
		entries.add(new SourceEntry(database, database.getFileName().toString()));
		entries.sort(Comparator.comparing(entry -> entry.name));

		Path target = uniqueTarget(resultsDirectory);
		try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target, StandardOpenOption.CREATE_NEW))) {
			for (SourceEntry source : entries) {
				zip.putNextEntry(new ZipEntry(source.name));
				Files.copy(source.path, zip);
				zip.closeEntry();
			}
		} catch (IOException e) {
			Files.deleteIfExists(target);
			throw e;
		}
		return target;
	}

	private static void collectFiles(Path base, Path directory, String prefix, List<SourceEntry> entries)
			throws IOException {
		try (Stream<Path> paths = Files.walk(directory)) {
			Iterator<Path> iterator = paths.iterator();
			while (iterator.hasNext()) {
				Path file = iterator.next();
				if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
						&& (prefix == null || file.getFileName().toString().startsWith(prefix))) {
					String name = base.relativize(file).toString().replace('\\', '/');
					entries.add(new SourceEntry(file, name));
				}
			}
		}
	}

	private static Path requireDirectory(Path path, String description) throws IOException {
		Path normalized = path.toAbsolutePath().normalize();
		if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException(description + " is unavailable: " + normalized);
		}
		return normalized;
	}

	private static Path requireFile(Path path, String description) throws IOException {
		Path normalized = path.toAbsolutePath().normalize();
		if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(normalized)) {
			throw new IOException(description + " is unavailable: " + normalized);
		}
		return normalized;
	}

	private static Path uniqueTarget(Path directory) {
		String baseName = "cct-results-" + PACKAGE_TIME.format(LocalDateTime.now());
		Path candidate = directory.resolve(baseName + ".zip");
		int suffix = 2;
		while (Files.exists(candidate)) candidate = directory.resolve(baseName + "-" + suffix++ + ".zip");
		return candidate;
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
