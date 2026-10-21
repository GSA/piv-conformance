package gov.gsa.pivconformance.gui;

import javax.swing.JPanel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;

import java.awt.HeadlessException;
import java.nio.file.Path;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JComboBox;
import javax.swing.JDialog;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.conformancelib.configuration.CardInfoController;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import gov.gsa.pivconformance.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.cardlib.utils.PCSCUtils;
import gov.gsa.pivconformance.cardlib.card.client.CardHandle;
import gov.gsa.pivconformance.cardlib.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.cardlib.card.client.PIVMiddleware;

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
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static final Logger s_logger = LoggerFactory.getLogger(SimpleTestExecutionPanel.class);
	
	private final JComboBox<String> m_readerComboBox;
	private final JPasswordField m_appPinField;
	private final JTextField m_databaseNameField;
	private final JTextField m_readerStatusField;
	private final JProgressBar m_testProgressBar;
	private final JButton m_runButton;
	private final JButton m_viewResultsButton;
	private final JButton m_packageResultsButton;
	private boolean m_refreshingReaders;
	public SimpleTestExecutionPanel() {
		setBackground(CctUi.CANVAS);
		setBorder(javax.swing.BorderFactory.createEmptyBorder(18, 22, 18, 22));
		
		JLabel lblCardReader = new JLabel("Card Reader");
		
		m_readerComboBox = new JComboBox<String>();
		m_readerComboBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (!m_refreshingReaders) configureSelectedReader();
			}
		});
		
		JLabel lblApplicationPin = new JLabel("PIV Application PIN");
		
		m_appPinField = new JPasswordField();
		m_appPinField.setColumns(10);
		
		JLabel lblTestDatabase = new JLabel("Test Database");
		
		m_databaseNameField = new JTextField();
		m_databaseNameField.setEditable(false);
		m_databaseNameField.setColumns(10);
		
		JLabel lblReaderStatus = new JLabel("Reader Status");
		
		m_readerStatusField = new JTextField();
		m_readerStatusField.setAlignmentX(Component.LEFT_ALIGNMENT);
		m_readerStatusField.setEditable(false);
		m_readerStatusField.setColumns(10);
		
		m_runButton = CctUi.button("Verify PIN and Execute Tests", true);
		m_runButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					//Armen -- Added this snippet to refresh card information before each run, otherwise if cards are swapped and 
					//run tests button is click tests fail.  Probably would be better to have an action that would detect
					//a new card do this when new card is detected but not sure how to do that right now
					int selected = m_readerComboBox.getSelectedIndex();
					CardSettingsSingleton css = CardSettingsSingleton.getInstance();
					resetCardSession(css);
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
						return;
					}
					if (!refreshReaderStatus(css)) return;
					
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
				GuiTestExecutionController tc = GuiTestExecutionController.getInstance();
				GuiTestCaseTreeNode root = GuiRunnerAppController.getInstance().getApp().getTreePanel().getRootNode();
				new Thread(() -> {
					tc.runAllTests(root);
				}).start();
				
			}
		});

		m_viewResultsButton = CctUi.button(GuiRunnerAppController.getInstance().getDisplayTestReportAction(), "View Test Results", false);
		m_viewResultsButton.setVisible(false);

		m_packageResultsButton = CctUi.button(GuiRunnerAppController.getInstance().getPackageResultsAction(), "Package Results", false);
		m_packageResultsButton.setVisible(false);
		
		m_testProgressBar = new JProgressBar();
		m_testProgressBar.setAlignmentY(Component.TOP_ALIGNMENT);
		
		JButton btnRefreshReaders = CctUi.button("Refresh Readers", false);
		btnRefreshReaders.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				refreshReaderState();
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
		lblCardReader.setLabelFor(m_readerComboBox);
		lblApplicationPin.setLabelFor(m_appPinField);
		lblTestDatabase.setLabelFor(m_databaseNameField);
		lblReaderStatus.setLabelFor(m_readerStatusField);
		for (JLabel label : new JLabel[] { lblCardReader, lblApplicationPin, lblTestDatabase, lblReaderStatus }) {
			label.setFont(CctUi.font(13, java.awt.Font.PLAIN));
			label.setForeground(CctUi.INK);
		}
		JPanel actions = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 8, 0));
		actions.setOpaque(false);
		actions.add(m_runButton);
		actions.add(m_viewResultsButton);
		actions.add(m_packageResultsButton);
		GroupLayout groupLayout = new GroupLayout(this);
		setLayout(groupLayout);
		groupLayout.setHorizontalGroup(groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
						.addGap(0, 0, Short.MAX_VALUE).addComponent(lblImage).addGap(0, 0, Short.MAX_VALUE))
				.addGroup(groupLayout.createSequentialGroup()
						.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addComponent(lblCardReader).addComponent(lblApplicationPin)
								.addComponent(lblTestDatabase).addComponent(lblReaderStatus))
						.addGap(16)
						.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addGroup(groupLayout.createSequentialGroup()
										.addComponent(m_readerComboBox, 120, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addGap(8).addComponent(btnRefreshReaders))
								.addGroup(groupLayout.createSequentialGroup()
										.addComponent(m_appPinField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
										.addGap(0, 0, Short.MAX_VALUE))
								.addComponent(m_databaseNameField, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(m_readerStatusField, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
				.addComponent(m_testProgressBar, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
				.addComponent(actions, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));
		groupLayout.setVerticalGroup(groupLayout.createSequentialGroup()
				.addGap(8).addComponent(lblImage).addGap(24)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblCardReader).addComponent(m_readerComboBox).addComponent(btnRefreshReaders))
				.addGap(18)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblApplicationPin).addComponent(m_appPinField))
				.addGap(18)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblTestDatabase).addComponent(m_databaseNameField))
				.addGap(18)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblReaderStatus).addComponent(m_readerStatusField))
				.addGap(20).addComponent(m_testProgressBar, GroupLayout.PREFERRED_SIZE, 23, GroupLayout.PREFERRED_SIZE)
				.addGap(12).addComponent(actions, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
				.addGap(0, 0, Short.MAX_VALUE));

		m_testProgressBar.setVisible(false);
		refreshReaderState();
		refreshDatabaseInfo();
		
	}

	public void refreshDatabaseInfo() {
		ConformanceTestDatabase db = GuiRunnerAppController.getInstance().getTestDatabase();
		if(db != null) {
			if(db.getConnection() != null) {
				Path databasePath = db.getDatabasePath();
				if(databasePath != null) {
					m_databaseNameField.setText(databasePath.toString());
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
		m_refreshingReaders = true;
		try {
			m_readerComboBox.removeAllItems();
			List<String> readers = PCSCUtils.GetConnectedReaders();
			for(String reader : readers) {
				m_readerComboBox.addItem(reader);
			}
			if(selectedReader != null && readers.contains(selectedReader)) {
				m_readerComboBox.setSelectedItem(selectedReader);
			} else {
				String reader = PCSCUtils.GetFirstReaderWithCardPresent();
				if(reader != null && readers.contains(reader)) {
					m_readerComboBox.setSelectedItem(reader);
				}
			}
		} finally {
			m_refreshingReaders = false;
		}
		configureSelectedReader();
	}

	private void configureSelectedReader() {
		int selected = m_readerComboBox.getSelectedIndex();
		s_logger.debug("Selected reader: {}: {}", selected, m_readerComboBox.getSelectedItem());
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		resetCardSession(css);
		css.setReaderIndex(selected);
		if (selected < 0) {
			css.setTerminal(null);
			m_readerStatusField.setText("No card reader connected.");
			return;
		}
		try {
			CardUtils.setUpReaderInSingleton();
		} catch (ConformanceTestException e) {
			s_logger.error("Caught ConformanceTestException setting up card reader", e);
			css.setTerminal(null);
			m_readerStatusField.setText("Unable to configure reader.");
			JOptionPane msgBox = new JOptionPane("Unable to configure reader: " + m_readerComboBox.getSelectedItem() + ".\n" +
					e.getMessage(), JOptionPane.ERROR_MESSAGE);
			JDialog dialog = msgBox.createDialog(this, "Error");
			dialog.setAlwaysOnTop(true);
			dialog.setVisible(true);
			return;
		}
		refreshReaderStatus(css);
	}

	static void resetCardSession(CardSettingsSingleton settings) {
		CardHandle handle = settings.getCardHandle();
		if (handle != null && handle.isValid() && handle.getCard() != null) {
			MiddlewareStatus result = PIVMiddleware.pivDisconnect(handle);
			if (result != MiddlewareStatus.PIV_OK) {
				s_logger.warn("Unable to disconnect previous card session: {}", result);
			}
		}
		settings.reset();
	}
	public JButton getRunButton() {
		return m_runButton;
	}

	public void setPostRunActionsVisible(boolean visible) {
		m_viewResultsButton.setVisible(visible);
		m_packageResultsButton.setVisible(visible);
		revalidate();
		repaint();
	}

	public boolean refreshReaderStatus(CardSettingsSingleton css) {
		CardTerminal reader = css.getTerminal();
		if(reader == null) { 
			m_readerStatusField.setText("");
			return false;
		}
		try {
			if(reader.isCardPresent()) {
				try {
					if (!CardUtils.setUpPivAppHandleInSingleton()) {
						m_readerStatusField.setText("Unable to connect to card.");
						return false;
					}
				} catch (ConformanceTestException e1) {
					s_logger.error("Unable to connect to card in reader", e1);
					m_readerStatusField.setText("Unable to connect to card.");
					JOptionPane msgBox = new JOptionPane("Unable to connect to reader: " + m_readerComboBox.getSelectedItem() + ".\n" +
							e1.getMessage(), JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
					return false;
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
				return atr != null;
			} else {
				m_readerStatusField.setText("No card present. Insert a card and click refresh.");
				return false;
			}
		} catch (HeadlessException | SecurityException | CardException e1) {
			s_logger.error("Failed to check card presence", e1);
			JOptionPane msgBox = new JOptionPane("Unable to connect to reader: " + m_readerComboBox.getSelectedItem() + ".\n" +
					e1.getMessage(), JOptionPane.ERROR_MESSAGE);
			JDialog dialog = msgBox.createDialog(SimpleTestExecutionPanel.this, "Error");
			dialog.setAlwaysOnTop(true);
			dialog.setVisible(true);
			return false;
		}
	}
}
