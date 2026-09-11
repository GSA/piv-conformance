package gov.gsa.pivconformance.gui;

import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.nio.file.Path;

import javax.swing.AbstractAction;
import javax.swing.Icon;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Creates a ZIP for the latest completed test run. */
final class PackageResultsAction extends AbstractAction {
	private static final long serialVersionUID = 1L;
	private static final Logger s_logger = LoggerFactory.getLogger(PackageResultsAction.class);
	private final ReviewPackageBuilder m_builder;
	private CompletedTestRun m_completedRun;

	PackageResultsAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
		m_builder = new ReviewPackageBuilder();
		setEnabled(false);
	}

	void setCompletedRun(CompletedTestRun completedRun) {
		m_completedRun = completedRun;
		setEnabled(completedRun != null);
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		packageCompletedRun();
	}

	void packageCompletedRun() {
		CompletedTestRun run = m_completedRun;
		if (run == null) {
			showError("No completed test run is available to package.");
			return;
		}
		setEnabled(false);
		new SwingWorker<Path, Void>() {
			@Override
			protected Path doInBackground() throws Exception {
				return m_builder.build(run);
			}

			@Override
			protected void done() {
				setEnabled(m_completedRun != null);
				try {
					Path packagePath = get();
					if (run == m_completedRun) showCompletion(packagePath);
				} catch (Exception e) {
					Throwable cause = e.getCause() == null ? e : e.getCause();
					s_logger.error("Unable to package test results", cause);
					showError("The results could not be packaged:\n" + cause.getMessage());
				}
			}
		}.execute();
	}

	private void showCompletion(Path packagePath) {
		Path path = packagePath.toAbsolutePath().normalize();
		Object[] options = { "Show in Folder", "Copy Path", "Close" };
		int choice = JOptionPane.showOptionDialog(GuiRunnerAppController.getInstance().getMainFrame(),
				"Results packaged successfully.\n\n" + path, "Results Packaged", JOptionPane.DEFAULT_OPTION,
				JOptionPane.INFORMATION_MESSAGE, null, options, options[2]);
		if (choice == 0) showInFolder(path);
		if (choice == 1) copyPath(path);
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
		try {
			Toolkit.getDefaultToolkit().getSystemClipboard()
					.setContents(new StringSelection(path.toString()), null);
		} catch (Exception e) {
			s_logger.error("Unable to copy the package path", e);
			showError("Unable to copy the package path. See console.log for details.");
		}
	}

	private void showError(String message) {
		JOptionPane.showMessageDialog(GuiRunnerAppController.getInstance().getMainFrame(), message,
				"Package Results Error", JOptionPane.ERROR_MESSAGE);
	}
}
