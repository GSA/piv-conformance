package gov.gsa.pivconformancegui;

import javax.swing.JPanel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;

import java.awt.Color;
import java.awt.HeadlessException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.LayoutStyle.ComponentPlacement;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.SwingUtilities;

import gov.gsa.conformancelib.configuration.CardInfoController;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.conformancelib.tests.ConformanceTestException;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.CachingDefaultPIVApplication;
import gov.gsa.pivconformance.utils.PCSCUtils;

import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.JButton;
import javax.swing.JProgressBar;
import java.awt.event.ActionListener;
import java.net.URL;
import java.awt.event.ActionEvent;
import javax.swing.SwingConstants;
import java.awt.Component;

public class SimpleTestExecutionPanel extends JPanel {
	
	private static final Logger s_logger = LoggerFactory.getLogger(SimpleTestExecutionPanel.class);
	
	private JComboBox<String> m_readerComboBox;
	private JPasswordField m_appPinField;
	private JTextField m_databaseNameField;
	private JTextField m_readerStatusField;
	private JProgressBar m_testProgressBar;
	private JButton m_runButton;
	public SimpleTestExecutionPanel() {
		setBackground(Color.WHITE);
		
		JLabel lblCardReader = new JLabel("Card Reader");
		
		m_readerComboBox = new JComboBox<String>();
		m_readerComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selected = m_readerComboBox.getSelectedIndex();
				s_logger.debug("Selected reader: {}: {}", selected, m_readerComboBox.getSelectedItem());
				CardSettingsSingleton css = CardSettingsSingleton.getInstance();
				css.setReaderIndex(selected);
				try {
					CardUtils.setUpReaderInSingleton();
				} catch (ConformanceTestException e1) {
					s_logger.error("Caught ConformanceTestException setting up card reader", e1);
					JOptionPane msgBox = new JOptionPane("Unable to configure reader: " + m_readerComboBox.getSelectedItem() + ".\n" +
							e1.getMessage(), JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
				}
				refreshReaderStatus(css);
				
			}
		});
		
		JLabel lblApplicationPin = new JLabel("PIV Application PIN");
		
		m_appPinField = new JPasswordField();
		m_appPinField.setColumns(10);
		
		JLabel lblTestDatabase = new JLabel("Test Database");
		
		m_databaseNameField = new JTextField();
		m_databaseNameField.setEditable(false);
		m_databaseNameField.setColumns(10);
		
		JButton btnOpenOtherDatabase = new JButton("Open Other Database...");
		// XXX *** TEMPORARY
		btnOpenOtherDatabase.setVisible(false);
		
		JLabel lblReaderStatus = new JLabel("Reader Status");
		
		m_readerStatusField = new JTextField();
		m_readerStatusField.setAlignmentX(Component.LEFT_ALIGNMENT);
		m_readerStatusField.setEditable(false);
		m_readerStatusField.setColumns(10);
		
		m_runButton = new JButton("Verify PIN and Execute Tests");
		m_runButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					//Armen -- Added this snippet to refresh card information before each run, otherwise if cards are swapped and 
					//run tests button is click tests fail.  Probably would be better to have an action that would detect
					//a new card do this when new card is detected but not sure how to do that right now
					int selected = m_readerComboBox.getSelectedIndex();
					CardSettingsSingleton css = CardSettingsSingleton.getInstance();
					css.reset();
					css.setReaderIndex(selected);
					try {
						CardUtils.setUpReaderInSingleton();
					} catch (ConformanceTestException e1) {
						s_logger.error("Caught ConformanceTestException setting up card reader", e1);
						JOptionPane msgBox = new JOptionPane("Unable to configure reader: " + m_readerComboBox.getSelectedItem() + ".\n" +
								e1.getMessage(), JOptionPane.ERROR_MESSAGE);
						JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
						dialog.setAlwaysOnTop(true);
						dialog.setVisible(true);
					}
					refreshReaderStatus(css);
					
					if(!CardUtils.setUpPivAppHandleInSingleton()) {
						s_logger.error("CardUtils.setUpPivAppHandleInSingleton() returned false");
						JOptionPane msgBox = new JOptionPane("Error connecting to card in order to verify PIN.", JOptionPane.ERROR_MESSAGE);
						JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
						dialog.setAlwaysOnTop(true);
						dialog.setVisible(true);
						return;
					}
				} catch (ConformanceTestException e1) {
					s_logger.error("Caught ConformanceTestException setting up PIV app handle", e);
					JOptionPane msgBox = new JOptionPane("Unable to connect to PIV in reader " + m_readerComboBox.getSelectedItem() + ".\n" +
							e1.getMessage(), JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
					return;
				}
				// first, check to make sure we have more than one retry remaining for application PIN
				int nRetries = CardInfoController.getAppPinRetries();
				if(nRetries == -1) {
					s_logger.error("Unable to check the number of PIN retries.");
					JOptionPane msgBox = new JOptionPane("Unable to verify PIN prior to testing. Confirm that the card is not locked before proceeding.", JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
					return;
				}
				s_logger.info("Application PIN: {} retries remain.", nRetries);
				if(m_appPinField.getPassword().length == 0) {
					JOptionPane msgBox = new JOptionPane("Application PIN is required.", JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
					return;
				}
				if(m_appPinField.getPassword().length < 6 || m_appPinField.getPassword().length > 8) {
					JOptionPane msgBox = new JOptionPane("Application PIN must be between 6 and 8 digits.", JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
					return;
				}
				CardSettingsSingleton css = CardSettingsSingleton.getInstance();
				css.setApplicationPin(new String(m_appPinField.getPassword()));
				try {
					if(!CardUtils.authenticateInSingleton(false)) {
						nRetries = CardInfoController.getAppPinRetries();
						JOptionPane msgBox = new JOptionPane("Incorrect application PIN. " + nRetries + " tries remain.", JOptionPane.ERROR_MESSAGE);
						JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
						dialog.setAlwaysOnTop(true);
						dialog.setVisible(true);
						return;
					}
				} catch (HeadlessException | SecurityException | ConformanceTestException e1) {
					s_logger.error("Caught exception authenticating to card", e1);
					JOptionPane msgBox = new JOptionPane("Unable to authenticate to PIV in reader " + m_readerComboBox.getSelectedItem() + ".\n" +
							e1.getMessage(), JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
					return;
				}
				TestExecutionController tc = TestExecutionController.getInstance();
				TestCaseTreeNode root = GuiRunnerAppController.getInstance().getApp().getTreePanel().getRootNode();
				new Thread(() -> {
					tc.runAllTests(root);
				}).start();
				
			}
		});
		
		m_testProgressBar = new JProgressBar();
		m_testProgressBar.setAlignmentY(Component.TOP_ALIGNMENT);
		
		JButton btnRefreshReaders = new JButton("Refresh Readers");
		btnRefreshReaders.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				refreshReaderState();
				refreshReaderStatus(CardSettingsSingleton.getInstance());
			}
		});
		
		String lblImageLocation = "/icons/gsa_logo.png";
		URL imageUrl = SimpleTestExecutionPanel.class.getResource(lblImageLocation);
		ImageIcon imageIcon = null;
		if(imageUrl == null) {
			s_logger.error("Unable to get image at classpath location {}", lblImageLocation);
		} else {
			imageIcon = new ImageIcon(imageUrl);
		}
		
		JLabel lblImage = new JLabel("[GSA Logo]");
		lblImage.setSize(50, 50);
		lblImage.setHorizontalAlignment(SwingConstants.CENTER);
		if(imageIcon != null) {
			lblImage.setIcon(imageIcon);
			lblImage.setText("");
		}
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(237)
							.addComponent(lblImage))
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(10)
							.addComponent(lblCardReader)
							.addGap(34)
							.addComponent(m_readerComboBox, GroupLayout.PREFERRED_SIZE, 507, GroupLayout.PREFERRED_SIZE))
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(10)
							.addComponent(lblApplicationPin)
							.addGap(425)
							.addComponent(m_appPinField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(10)
							.addComponent(lblTestDatabase)
							.addGap(25)
							.addComponent(m_databaseNameField, GroupLayout.PREFERRED_SIZE, 507, GroupLayout.PREFERRED_SIZE))
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(10)
							.addComponent(lblReaderStatus)
							.addGap(26)
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addComponent(btnOpenOtherDatabase)
								.addComponent(m_readerStatusField, GroupLayout.PREFERRED_SIZE, 507, GroupLayout.PREFERRED_SIZE))))
					.addGap(103))
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addComponent(m_testProgressBar, GroupLayout.DEFAULT_SIZE, 602, Short.MAX_VALUE)
					.addContainerGap())
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(106)
					.addComponent(btnRefreshReaders, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(m_runButton)
					.addGap(317))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(20)
					.addComponent(lblImage)
					.addGap(20)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(3)
							.addComponent(lblCardReader))
						.addComponent(m_readerComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGap(20)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(3)
							.addComponent(lblApplicationPin))
						.addComponent(m_appPinField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGap(20)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(3)
							.addComponent(lblTestDatabase))
						.addComponent(m_databaseNameField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(27)
							.addComponent(lblReaderStatus))
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(25)
							.addComponent(m_readerStatusField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
					.addGap(18)
					.addComponent(btnOpenOtherDatabase)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(m_testProgressBar, GroupLayout.PREFERRED_SIZE, 23, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(btnRefreshReaders)
						.addComponent(m_runButton))
					.addContainerGap(230, Short.MAX_VALUE))
		);
		setLayout(groupLayout);
		
		
		m_testProgressBar.setVisible(false);
		refreshReaderState();
		refreshDatabaseInfo();
		refreshReaderStatus(CardSettingsSingleton.getInstance());
		
	}

	public void refreshDatabaseInfo() {
		ConformanceTestDatabase db = GuiRunnerAppController.getInstance().getTestDatabase();
		if(db != null) {
			Connection c = db.getConnection();
			if(c != null) {
				String filename = null;
				try {
					filename = c.getClientInfo("filename");
				} catch (SQLException e) {
					m_databaseNameField.setText("No filename information is available.");
				}
				if(filename != null) {
					m_databaseNameField.setText(filename);
				} else {
					m_databaseNameField.setText("(unavailable)");
				}
			} else {
				m_databaseNameField.setText("No active database");
			}
		} else {
			m_databaseNameField.setText("No database is currently open.");
		}
	}
	
	public JComboBox<String> getReaderComboBox() {
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
	private void refreshReaderState() {
		String selectedReader = (String) m_readerComboBox.getSelectedItem();
		m_readerComboBox.removeAllItems();
		
		List<String> readers = PCSCUtils.GetConnectedReaders();
		for(String reader : readers) {
			m_readerComboBox.addItem(reader);
		}
		if(selectedReader != null) {
			m_readerComboBox.setSelectedItem(selectedReader);
		} else {
			String reader = PCSCUtils.GetFirstReaderWithCardPresent();
			if(reader != null) {
				m_readerComboBox.setSelectedItem(reader);
			}
		}
	}
	public JButton getRunButton() {
		return m_runButton;
	}

	public void refreshReaderStatus(CardSettingsSingleton css) {
		CardTerminal reader = css.getTerminal();
		if(reader == null) { 
			m_readerStatusField.setText("");
			return;
		}
		try {
			if(reader.isCardPresent()) {
				try {
					CardUtils.setUpPivAppHandleInSingleton();
				} catch (ConformanceTestException e1) {
					s_logger.error("Unable to connect to card in reader", e1);
					JOptionPane msgBox = new JOptionPane("Unable to connect to reader: " + m_readerComboBox.getSelectedItem() + ".\n" +
							e1.getMessage(), JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
				}
				String status = null;
				byte[] atr = CardInfoController.getATR();
				if(atr != null) {
					String hexAtr = Hex.encodeHexString(atr);
					status = "Card present: " + hexAtr;
				} else {
					status = "Unable to connect to card";
				}
				m_readerStatusField.setText(status);
			} else {
				m_readerStatusField.setText("No card present. Insert a card and click refresh.");
			}
		} catch (HeadlessException | SecurityException | CardException e1) {
			s_logger.error("Failed to check card presence", e1);
			JOptionPane msgBox = new JOptionPane("Unable to connect to reader: " + m_readerComboBox.getSelectedItem() + ".\n" +
					e1.getMessage(), JOptionPane.ERROR_MESSAGE);
			JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
			dialog.setAlwaysOnTop(true);
			dialog.setVisible(true);
		}
	}
}
