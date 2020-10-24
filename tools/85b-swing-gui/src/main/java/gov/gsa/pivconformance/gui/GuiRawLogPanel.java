package gov.gsa.pivconformance.gui;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class GuiRawLogPanel extends JPanel {

	private static final long serialVersionUID = -91080473504561866L;
	private JTextPane m_debugTextPane;
	
	public GuiRawLogPanel() {
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
		btnNewButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				m_debugTextPane.setText("");
			}
		});
		buttonPane.add(btnNewButton);
		add(buttonPane);
	}

	public JTextPane getDebugTextPane() {
		return m_debugTextPane;
	}
}
