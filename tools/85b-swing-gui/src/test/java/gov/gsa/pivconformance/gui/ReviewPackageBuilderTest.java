package gov.gsa.pivconformance.gui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import gov.gsa.pivconformance.conformancelib.configuration.ConformanceTestDatabase;

class ReviewPackageBuilderTest {
	private static final String PREFIX = "card-identifier_20260819_010203-20260819_020304";

	@TempDir
	Path tempDirectory;

	@ParameterizedTest
	@ValueSource(strings = { "PIV_Production_Cards.db", "PIV-I_Production_Cards.db" })
	void packagesExactlyOneCompletedRunAndSelectedDatabase(String databaseName) throws Exception {
		Path database = createEvidence(databaseName, "database");
		write("logs/conformancelog/" + PREFIX + "-conformance_results.csv",
				"Date,Test Id,Description,Expected Result,Actual Result\n"
				+ "2026-08-19 01:02:04,1,one,Pass,Pass\n"
				+ "2026-08-19 01:02:05,2,two,Pass,Fail\n");
		write("logs/apdu/" + PREFIX + "-apdu_transmission.log", "masked APDU aa aa aa");
		write("logs/conformancelog/old-run-conformance_results.csv", "stale");
		write("logs/debug/debug.log", "temporary");
		write("piv-artifacts/" + PREFIX + "-chuid.bin", "current piv artifact");
		write("piv-artifacts/old-run-chuid.bin", "stale piv artifact");
		write("x509-artifacts/" + PREFIX + "-authentication.crt", "current certificate artifact");
		write("x509-certs/cacerts.jks", "trust store");
		write("x509-certs/valid/policy.xml", "policy");
		write("unused.db", "unused database");
		write("tool.jar", "executable");
		write("cct-results-20200101-000000.zip", "old package");

		Path result = new ReviewPackageBuilder().build(completedRun(database));

		assertTrue(result.getFileName().toString().startsWith("cct-results-"));
		assertTrue(result.getFileName().toString().endsWith(".zip"));
		assertEquals(Arrays.asList(
				databaseName,
				"logs/apdu/" + PREFIX + "-apdu_transmission.log",
				"logs/conformancelog/" + PREFIX + "-conformance_results.csv",
				"piv-artifacts/" + PREFIX + "-chuid.bin",
				"x509-artifacts/" + PREFIX + "-authentication.crt",
				"x509-certs/cacerts.jks",
				"x509-certs/valid/policy.xml"), zipEntries(result));
		assertFalse(result.getFileName().toString().contains("card-identifier"));
	}

	@Test
	void preservesLegacyEvidenceBytesUnchanged() throws Exception {
		Path database = createEvidence("PIV_ICAM_Test_Cards.db", "database");
		basicCsv();
		byte[] evidence = new byte[] { 0x00, 0x31, 0x32, 0x33, 0x34, (byte) 0xff, 0x0a };
		Path apdu = writeBytes("logs/apdu/" + PREFIX + "-apdu_transmission.log", evidence);
		Path result = new ReviewPackageBuilder().build(completedRun(database));
		assertArrayEquals(Files.readAllBytes(apdu),
				zipEntry(result, "logs/apdu/" + apdu.getFileName()));
	}

	@Test
	void createsAUniquePackageWithoutOverwritingEarlierResults() throws Exception {
		Path database = createEvidence("PIV_Production_Cards.db", "database");
		basicCsv();
		ReviewPackageBuilder builder = new ReviewPackageBuilder();

		Path first = builder.build(completedRun(database));
		Path second = builder.build(completedRun(database));

		assertNotEquals(first, second);
		assertTrue(Files.isRegularFile(first));
		assertTrue(Files.isRegularFile(second));
	}

	@Test
	void packageActionTracksCompletedRunAvailability() throws Exception {
		PackageResultsAction action = new PackageResultsAction("Package", null, "Package results");
		assertFalse(action.isEnabled());

		Path database = createEvidence("PIV_Production_Cards.db", "database");
		basicCsv();
		action.setCompletedRun(completedRun(database));
		assertTrue(action.isEnabled());

		action.setCompletedRun(null);
		assertFalse(action.isEnabled());
	}

	@Test
	void retainsCanonicalSelectedDatabasePathWithoutJdbcClientInfo() throws Exception {
		Path database = tempDirectory.resolve("databases").resolve("selected.db");
		Files.createDirectories(database.getParent());
		Files.createFile(database);
		Path nonCanonicalPath = database.getParent().resolve("..").resolve("databases").resolve("selected.db");
		ConformanceTestDatabase selected = new ConformanceTestDatabase(null);

		try {
			selected.openDatabaseInFile(nonCanonicalPath.toString());
			assertEquals(database.toRealPath(), selected.getDatabasePath());
		} finally {
			if (selected.getConnection() != null) selected.getConnection().close();
		}
	}

	@Test
	void rejectsMissingCompletedRunAndAmbiguousCsv() throws Exception {
		ReviewPackageBuilder builder = new ReviewPackageBuilder();
		assertThrows(IllegalStateException.class, () -> builder.build(null));

		Path database = createEvidence("PIV_Production_Cards.db", "database");
		basicCsv();
		write("logs/other/" + PREFIX + "-second.csv", "Date,Actual Result\nnow,Pass\n");
		CompletedTestRun run = completedRun(database);
		IOException error = assertThrows(IOException.class, () -> builder.build(run));
		assertTrue(error.getMessage().contains("exactly one conformance CSV"));
	}

	private Path basicCsv() throws IOException {
		createEvidence("x509-certs/cacerts.jks", "trust");
		return write("logs/conformancelog/" + PREFIX + "-conformance_results.csv",
				"Date,Test Id,Description,Expected Result,Actual Result\n"
				+ "now,1,one,Pass,Pass\nnow,2,two,Pass,Fail\n");
	}

	private CompletedTestRun completedRun(Path database) {
		return new CompletedTestRun(tempDirectory, database, PREFIX);
	}

	private Path createEvidence(String relative, String contents) throws IOException {
		return write(relative, contents);
	}

	private Path write(String relative, String contents) throws IOException {
		return writeBytes(relative, contents.getBytes(StandardCharsets.UTF_8));
	}

	private Path writeBytes(String relative, byte[] contents) throws IOException {
		Path path = tempDirectory.resolve(relative);
		Files.createDirectories(path.getParent());
		Files.write(path, contents);
		return path;
	}

	private static List<String> zipEntries(Path zipPath) throws IOException {
		List<String> names = new ArrayList<>();
		try (ZipFile zip = new ZipFile(zipPath.toFile())) {
			Enumeration<? extends ZipEntry> entries = zip.entries();
			while (entries.hasMoreElements()) names.add(entries.nextElement().getName());
		}
		return names;
	}

	private static byte[] zipEntry(Path zipPath, String name) throws IOException {
		try (ZipFile zip = new ZipFile(zipPath.toFile())) {
			ZipEntry entry = zip.getEntry(name);
			assertTrue(entry != null, name);
			return zip.getInputStream(entry).readAllBytes();
		}
	}
}
