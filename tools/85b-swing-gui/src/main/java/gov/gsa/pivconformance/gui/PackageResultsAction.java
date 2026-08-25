package gov.gsa.pivconformance.gui;

import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.Icon;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Creates a local Review Manager ZIP and offers safe handoff actions. */
public class PackageResultsAction extends AbstractAction {
	private static final long serialVersionUID = 1L;
	private static final Logger s_logger = LoggerFactory.getLogger(PackageResultsAction.class);
	private static final String REVIEW_MANAGER_PROPERTY = "piv.reviewManager.url";
	private static final String REVIEW_MANAGER_ENVIRONMENT = "PIV_REVIEW_MANAGER_URL";
	private final ReviewPackageBuilder m_builder;
	private CompletedTestRun m_completedRun;

	public PackageResultsAction(String name, Icon icon, String toolTip) {
		this(name, icon, toolTip, new ReviewPackageBuilder());
	}

	PackageResultsAction(String name, Icon icon, String toolTip, ReviewPackageBuilder builder) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
		m_builder = builder;
		setEnabled(false);
	}

	public void setCompletedRun(CompletedTestRun completedRun) {
		m_completedRun = completedRun;
		setEnabled(completedRun != null);
	}

	public CompletedTestRun getCompletedRun() {
		return m_completedRun;
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		packageCompletedRun();
	}

	void packageCompletedRun() {
		final CompletedTestRun run = m_completedRun;
		if (run == null) {
			showError("No successfully completed test run is available to package.");
			return;
		}
		setEnabled(false);
		new SwingWorker<ReviewPackage, Void>() {
			@Override
			protected ReviewPackage doInBackground() throws Exception {
				return m_builder.build(run);
			}

			@Override
			protected void done() {
				setEnabled(m_completedRun != null);
				try {
					ReviewPackage reviewPackage = get();
					if (run == m_completedRun) {
						showCompletion(reviewPackage);
					} else {
						s_logger.info("Review package created at {} after a newer test run started",
								reviewPackage.getPath());
					}
				} catch (Exception e) {
					Throwable cause = e.getCause() == null ? e : e.getCause();
					s_logger.error("Unable to create Review Manager package", cause);
					showError("The review package could not be created:\n" + cause.getMessage());
				}
			}
		}.execute();
	}

	private void showCompletion(ReviewPackage reviewPackage) {
		URI reviewManager = configuredReviewManagerUri();
		List<String> options = new ArrayList<>();
		options.add("Show in Folder");
		options.add("Copy Path");
		if (reviewManager != null) options.add("Open Review Manager");
		options.add("Close");

		Path path = reviewPackage.getPath().toAbsolutePath().normalize();
		String message = "Review package created locally.\n\n"
				+ "File: " + path.getFileName() + "\n"
				+ "Path: " + path + "\n"
				+ "Size: " + humanSize(reviewPackage.getSize()) + " (" + reviewPackage.getSize() + " bytes)\n"
				+ "SHA-256: " + reviewPackage.getSha256() + "\n\n"
				+ "No files were uploaded. Select or drag this ZIP into Review Manager.";
		int choice = JOptionPane.showOptionDialog(GuiRunnerAppController.getInstance().getMainFrame(), message,
				"Package Results for Review Manager", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE,
				null, options.toArray(), options.get(options.size() - 1));
		if (choice < 0) return;
		String selected = options.get(choice);
		if ("Show in Folder".equals(selected)) {
			showInFolder(path);
		} else if ("Copy Path".equals(selected)) {
			copyPath(path);
		} else if ("Open Review Manager".equals(selected)) {
			openReviewManager(reviewManager);
		}
	}

	private void showInFolder(Path path) {
		try {
			if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
				throw new IOException("Opening folders is not supported on this system");
			}
			Desktop.getDesktop().open(path.getParent().toFile());
		} catch (Exception e) {
			showError("Unable to show the package folder:\n" + e.getMessage());
		}
	}

	private void copyPath(Path path) {
		copyText(path.toString(), "Unable to copy the package path");
	}

	private void copyText(String value, String errorSummary) {
		try {
			Toolkit.getDefaultToolkit().getSystemClipboard()
					.setContents(new StringSelection(value), null);
		} catch (Exception e) {
			s_logger.error(errorSummary, e);
			JOptionPane.showMessageDialog(GuiRunnerAppController.getInstance().getMainFrame(),
					errorSummary + ". See console.log for details.", "Copy Failed", JOptionPane.ERROR_MESSAGE);
		}
	}

	private void openReviewManager(URI uri) {
		try {
			if (uri == null) throw new IOException("No Review Manager URL is configured");
			if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
				throw new IOException("Opening a browser is not supported on this system");
			}
			Desktop.getDesktop().browse(uri);
		} catch (Exception e) {
			showError("Unable to open Review Manager:\n" + e.getMessage());
		}
	}

	static URI configuredReviewManagerUri() {
		String configured = System.getProperty(REVIEW_MANAGER_PROPERTY);
		if (configured == null || configured.trim().isEmpty()) {
			configured = System.getenv(REVIEW_MANAGER_ENVIRONMENT);
		}
		if (configured == null || configured.trim().isEmpty()) return null;
		try {
			URI uri = new URI(configured.trim());
			if (!("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
					|| uri.getHost() == null) {
				s_logger.warn("Ignoring invalid Review Manager URL configured in {} or {}",
						REVIEW_MANAGER_PROPERTY, REVIEW_MANAGER_ENVIRONMENT);
				return null;
			}
			return uri;
		} catch (URISyntaxException e) {
			s_logger.warn("Ignoring malformed Review Manager URL", e);
			return null;
		}
	}

	private static String humanSize(long bytes) {
		if (bytes < 1024) return bytes + " B";
		double kib = bytes / 1024.0;
		if (kib < 1024) return String.format("%.1f KiB", kib);
		return String.format("%.1f MiB", kib / 1024.0);
	}

	private void showError(String message) {
		JOptionPane.showMessageDialog(GuiRunnerAppController.getInstance().getMainFrame(), message,
				"Package Results Error", JOptionPane.ERROR_MESSAGE);
	}
}
