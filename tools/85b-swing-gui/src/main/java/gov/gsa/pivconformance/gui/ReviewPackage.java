package gov.gsa.pivconformance.gui;

import java.nio.file.Path;

/** Details shown to the operator after a local review package is created. */
public final class ReviewPackage {
	private final Path m_path;
	private final long m_size;
	private final String m_sha256;

	public ReviewPackage(Path path, long size, String sha256) {
		m_path = path;
		m_size = size;
		m_sha256 = sha256;
	}

	public Path getPath() { return m_path; }
	public long getSize() { return m_size; }
	public String getSha256() { return m_sha256; }
}
