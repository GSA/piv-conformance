package gov.gsa.pivconformancegui;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;

public class RawLogPanel extends JPanel {
	public RawLogPanel() {
		super();
		this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		m_debugTextPane = new JTextPane();
		m_debugTextPane.setEditable(false);
		add(m_debugTextPane);
		JScrollPane scrollPane = new JScrollPane(m_debugTextPane);
		add(scrollPane);
		
		JPanel buttonPane = new JPanel();
		buttonPane.setLayout(new BoxLayout(buttonPane, BoxLayout.X_AXIS));
		buttonPane.setBorder(BorderFactory.createEmptyBorder(0,10,10,10));
		buttonPane.add(Box.createHorizontalGlue());
		JButton btnNewButton = new JButton("Clear");
		buttonPane.add(btnNewButton);
		add(buttonPane);
		
		
	}

	private static final long serialVersionUID = -91080473504561866L;
	private JTextPane m_debugTextPane;

	public JTextPane getDebugTextPane() {
		return m_debugTextPane;
	}
}
