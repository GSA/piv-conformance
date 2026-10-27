package gov.gsa.pivconformance.gui;

import java.awt.Desktop;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.nio.file.Path;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
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
					if (run == m_completedRun) showError("The results could not be packaged:\n" + cause.getMessage());
				}
			}
		}.execute();
	}

	private void showCompletion(Path packagePath) {
		JDialog dialog = new JDialog(GuiRunnerAppController.getInstance().getMainFrame(), "Results Packaged", true);
		dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
		CompletionContent content = completionContent(packagePath, dialog::dispose);
		dialog.setContentPane(content.panel());
		dialog.getRootPane().setDefaultButton(content.done());
		dialog.getRootPane().registerKeyboardAction(e -> dialog.dispose(),
				javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0),
				javax.swing.JComponent.WHEN_IN_FOCUSED_WINDOW);
		dialog.pack();
		dialog.setLocationRelativeTo(GuiRunnerAppController.getInstance().getMainFrame());
		dialog.setVisible(true);
	}

	/** Kept separate from the top-level window so the actual dialog content can be checked headlessly. */
	CompletionContent completionContent(Path packagePath, Runnable dismiss) {
		Path path = packagePath.toAbsolutePath().normalize();
		JPanel content = new JPanel(new BorderLayout(0, 18));
		content.setBackground(CctUi.CANVAS);
		content.setBorder(BorderFactory.createEmptyBorder(24, 26, 22, 26));
		JLabel heading = new JLabel("Your results package is ready");
		heading.setFont(CctUi.font(21, Font.BOLD));
		heading.setForeground(new Color(0x067647));
		content.add(heading, BorderLayout.NORTH);
		JTextArea location = new JTextArea("The ZIP contains this run's database, logs and artifacts"
				+ (m_completedRun.getResults() == null ? "." : ", plus its readable results summary.")
				+ "\n\n" + path);
		location.setEditable(false);
		location.setOpaque(false);
		location.setLineWrap(true);
		location.setWrapStyleWord(true);
		location.setColumns(54);
		location.setRows(5);
		location.getAccessibleContext().setAccessibleName("Results ZIP location");
		content.add(location, BorderLayout.CENTER);
		JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
		buttons.setOpaque(false);
		JButton folder = CctUi.button("Show in Folder", false);
		folder.addActionListener(e -> showInFolder(path));
		JButton copy = CctUi.button("Copy Path", false);
		copy.addActionListener(e -> { if (copyPath(path)) copy.setText("Copied"); });
		JButton view = CctUi.button("View Results", false);
		view.setEnabled(m_completedRun.getResults() != null);
		view.addActionListener(e -> {
			dismiss.run();
			GuiRunnerAppController.getInstance().getDisplayTestReportAction().actionPerformed(e);
		});
		JButton close = CctUi.button("Done", true);
		close.addActionListener(e -> dismiss.run());
		buttons.add(folder);
		buttons.add(copy);
		buttons.add(view);
		buttons.add(close);
		content.add(buttons, BorderLayout.SOUTH);
		return new CompletionContent(content, close);
	}

	record CompletionContent(JPanel panel, JButton done) { }

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

	private boolean copyPath(Path path) {
		try {
			Toolkit.getDefaultToolkit().getSystemClipboard()
					.setContents(new StringSelection(path.toString()), null);
			return true;
		} catch (Exception e) {
			s_logger.error("Unable to copy the package path", e);
			showError("Unable to copy the package path. See console.log for details.");
			return false;
		}
	}

	private void showError(String message) {
		JOptionPane.showMessageDialog(GuiRunnerAppController.getInstance().getMainFrame(), message,
				"Package Results Error", JOptionPane.ERROR_MESSAGE);
	}
}
