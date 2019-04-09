package gov.gsa.pivconformancegui;

import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import java.awt.Color;
import javax.swing.JLabel;
import javax.swing.JComboBox;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.JButton;
import javax.swing.JProgressBar;

public class SimpleTestExecutionPanel extends JPanel {
	private JComboBox m_readerComboBox;
	private JPasswordField m_appPinField;
	private JTextField m_databaseNameField;
	private JTextField m_readerStatusField;
	private JProgressBar m_testProgressBar;
	public SimpleTestExecutionPanel() {
		setBackground(Color.WHITE);
		
		JLabel lblCardReader = new JLabel("Card Reader");
		
		m_readerComboBox = new JComboBox();
		
		JLabel lblApplicationPin = new JLabel("Application PIN");
		
		m_appPinField = new JPasswordField();
		m_appPinField.setColumns(10);
		
		JLabel lblTestDatabase = new JLabel("Test Database");
		
		m_databaseNameField = new JTextField();
		m_databaseNameField.setColumns(10);
		
		JButton btnOpenOtherDatabase = new JButton("Open Other Database...");
		
		JLabel lblReaderStatus = new JLabel("Reader Status");
		
		m_readerStatusField = new JTextField();
		m_readerStatusField.setColumns(10);
		
		JButton btnVerifyPinAnd = new JButton("Verify PIN and Execute Tests");
		
		m_testProgressBar = new JProgressBar();
		
		JButton btnRefreshReaders = new JButton("Refresh Readers");
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addContainerGap()
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addGroup(groupLayout.createSequentialGroup()
									.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
										.addComponent(lblCardReader)
										.addComponent(lblApplicationPin))
									.addPreferredGap(ComponentPlacement.RELATED)
									.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
										.addComponent(m_readerComboBox, 0, 310, Short.MAX_VALUE)
										.addComponent(m_appPinField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
								.addGroup(groupLayout.createSequentialGroup()
									.addComponent(lblTestDatabase)
									.addPreferredGap(ComponentPlacement.UNRELATED)
									.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
										.addComponent(btnOpenOtherDatabase)
										.addComponent(m_databaseNameField, GroupLayout.DEFAULT_SIZE, 311, Short.MAX_VALUE)))
								.addGroup(groupLayout.createSequentialGroup()
									.addComponent(lblReaderStatus)
									.addPreferredGap(ComponentPlacement.UNRELATED)
									.addComponent(m_readerStatusField, GroupLayout.DEFAULT_SIZE, 311, Short.MAX_VALUE)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(btnRefreshReaders))))
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(159)
							.addComponent(btnVerifyPinAnd))
						.addGroup(Alignment.TRAILING, groupLayout.createSequentialGroup()
							.addContainerGap()
							.addComponent(m_testProgressBar, GroupLayout.DEFAULT_SIZE, 426, Short.MAX_VALUE)))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(47)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblCardReader)
						.addComponent(m_readerComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblApplicationPin)
						.addComponent(m_appPinField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblTestDatabase)
						.addComponent(m_databaseNameField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
						.addGroup(groupLayout.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(btnOpenOtherDatabase)
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
								.addComponent(lblReaderStatus)
								.addComponent(m_readerStatusField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
							.addPreferredGap(ComponentPlacement.RELATED, 36, Short.MAX_VALUE))
						.addGroup(groupLayout.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(btnRefreshReaders)
							.addGap(18)))
					.addComponent(m_testProgressBar, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
					.addGap(18)
					.addComponent(btnVerifyPinAnd)
					.addContainerGap())
		);
		setLayout(groupLayout);
		m_testProgressBar.setVisible(false);
	}
	public JComboBox getReaderComboBox() {
		return m_readerComboBox;
	}
	public JTextField getReaderStatusField() {
		return m_readerStatusField;
	}
	public JTextField getDatabaseNameField() {
		return m_databaseNameField;
	}
	public JProgressBar getTestProgressBar() {
		return m_testProgressBar;
	}
}
