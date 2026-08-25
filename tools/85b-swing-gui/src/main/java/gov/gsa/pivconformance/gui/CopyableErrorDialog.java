package gov.gsa.pivconformance.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Displays bounded, selectable diagnostics without stretching across the screen. */
final class CopyableErrorDialog {
	private static final Logger s_logger = LoggerFactory.getLogger(CopyableErrorDialog.class);

	private CopyableErrorDialog() { }

	static void show(Component parent, String title, String summary, String detailsText) {
		String details = detailsText == null || detailsText.trim().isEmpty()
				? "No additional details are available. See console.log for the full application log."
				: detailsText;
		JTextArea textArea = createDetails(details);
		JScrollPane scrollPane = new JScrollPane(textArea);
		scrollPane.setPreferredSize(new Dimension(640, 180));
		JPanel content = new JPanel(new BorderLayout(0, 8));
		content.add(new JLabel(summary), BorderLayout.NORTH);
		content.add(scrollPane, BorderLayout.CENTER);
		content.add(new JLabel("The full diagnostic is also available in console.log."), BorderLayout.SOUTH);
		Object[] options = { "Copy Details", "Close" };
		int choice = JOptionPane.showOptionDialog(parent, content, title, JOptionPane.DEFAULT_OPTION,
				JOptionPane.ERROR_MESSAGE, null, options, options[1]);
		if (choice == 0) copy(details, parent);
	}

	static JTextArea createDetails(String details) {
		JTextArea textArea = new JTextArea(details, 8, 72);
		textArea.setEditable(false);
		textArea.setLineWrap(true);
		textArea.setWrapStyleWord(true);
		textArea.setCaretPosition(0);
		return textArea;
	}

	private static void copy(String details, Component parent) {
		try {
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(details), null);
		} catch (Exception e) {
			s_logger.error("Unable to copy error details", e);
			JOptionPane.showMessageDialog(parent, "Unable to copy the details. See console.log instead.",
					"Copy Failed", JOptionPane.ERROR_MESSAGE);
		}
	}
}
