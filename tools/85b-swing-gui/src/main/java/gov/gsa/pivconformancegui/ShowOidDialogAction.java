package gov.gsa.pivconformancegui;

import java.awt.Font;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.AbstractAction;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.JOptionPane;
import javax.swing.UIManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.FormSpecs;
import com.jgoodies.forms.layout.RowSpec;

import gov.gsa.conformancelib.configuration.ConfigurationException;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;

public class ShowOidDialogAction extends AbstractAction {

	/**
	 * 
	 */
	private static JFrame m_frame = new JFrame();
	private static final long serialVersionUID = 1L;
	private static final Logger s_logger = LoggerFactory.getLogger(ShowOidDialogAction.class);
	final static String toolTip = "Enter pipe-separated list of possible certificate policy OIDs (logically ORd)";

	static {
		JFrame frame = new JFrame();
		m_frame = frame;
        frame.getContentPane().setBackground(UIManager.getColor("Button.background"));
        frame.setAlwaysOnTop(true);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(619,287);
        frame.setTitle("Certificate Policy OID Overrides");
        frame.getContentPane().setLayout(new FormLayout(new ColumnSpec[] {
        		FormSpecs.RELATED_GAP_COLSPEC,
        		ColumnSpec.decode("max(75dlu;min)"),
        		ColumnSpec.decode("8dlu"),
        		ColumnSpec.decode("max(150dlu;min)"),
        		ColumnSpec.decode("max(150dlu;min)"),
        		FormSpecs.RELATED_GAP_COLSPEC,},
        	new RowSpec[] {
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		FormSpecs.DEFAULT_ROWSPEC,
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("20px"),
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("20px"),
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("20px"),
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("20px"),
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("20px"),
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("20px"),
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("20px"),
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("max(20px;default)"),
        		FormSpecs.RELATED_GAP_ROWSPEC,}));
        
        JTextArea txtDefinitionTextArea = new JTextArea();
        txtDefinitionTextArea.setWrapStyleWord(true);
        txtDefinitionTextArea.setBackground(UIManager.getColor("Button.background"));
        txtDefinitionTextArea.setEnabled(false);
        txtDefinitionTextArea.setFont(new Font("Tahoma", Font.PLAIN, 11));
        txtDefinitionTextArea.setLineWrap(true);
        txtDefinitionTextArea.setText("This form allows you to override the certificate policy OIDs that the tool checks for each type of certificate.  If your certificates assert different policy OIDs, complete this form to ensure the tool tests for your OIDs.");
        frame.getContentPane().add(txtDefinitionTextArea, "2, 2, 4, 1, fill, top");
        
        JLabel lblPivAuthentication = new JLabel("PIV Authentication");
        frame.getContentPane().add(lblPivAuthentication, "2, 4, right, default");
        
        JTextField pivAuthOverrideTextField = new JTextField();
        pivAuthOverrideTextField.setToolTipText(toolTip);
        frame.getContentPane().add(pivAuthOverrideTextField, "4, 4, 2, 1");
        pivAuthOverrideTextField.setColumns(10);
        
        JLabel lblDigitalSignature = new JLabel("Digital Signature");
        frame.getContentPane().add(lblDigitalSignature, "2, 6, right, default");
        
        JTextField digitalSignatureOverrideTextField = new JTextField();
        digitalSignatureOverrideTextField.setToolTipText(toolTip);
        frame.getContentPane().add(digitalSignatureOverrideTextField, "4, 6, 2, 1");
        digitalSignatureOverrideTextField.setColumns(10);
        
        JLabel lblKeyManagement = new JLabel("Key Management");
        frame.getContentPane().add(lblKeyManagement, "2, 8, right, default");
        
        JTextField keyManagementOverrideTextField = new JTextField();
        keyManagementOverrideTextField.setToolTipText(toolTip);
        frame.getContentPane().add(keyManagementOverrideTextField, "4, 8, 2, 1");
        keyManagementOverrideTextField.setColumns(10);
        
        JLabel lblCardAuthentication = new JLabel("Card Authentication");
        frame.getContentPane().add(lblCardAuthentication, "2, 10, right, default");
        
        JTextField cardAuthenticationOverrideTextField = new JTextField();
        cardAuthenticationOverrideTextField.setToolTipText(toolTip);
        frame.getContentPane().add(cardAuthenticationOverrideTextField, "4, 10, 2, 1");
        cardAuthenticationOverrideTextField.setColumns(10);
        
        JLabel lblContentSigning = new JLabel("Content Signing");
        frame.getContentPane().add(lblContentSigning, "2, 12, right, default");
        
        JTextField contentSigningOverrideTextField = new JTextField();
        contentSigningOverrideTextField.setToolTipText(toolTip);
        frame.getContentPane().add(contentSigningOverrideTextField, "4, 12, 2, 1");
        contentSigningOverrideTextField.setColumns(10);
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(new ActionListener() {
        	public void actionPerformed(ActionEvent e) {
        	}
        });
        
        JButton saveButton = new JButton("Save");
        frame.getContentPane().add(saveButton, "4, 16, right, default");	
        
        saveButton.addActionListener(new ActionListener()  {
			@Override
			public void actionPerformed(ActionEvent e) {
				s_logger.debug("Save override OIDS action performed");

				// TODO: Save changes to database
				ConformanceTestDatabase db = new ConformanceTestDatabase(null);
				String path = GuiRunnerAppController.getInstance().getApp().getMainContent().getTestExecutionPanel().getDatabaseNameField().getText();
				try {
					db.openDatabaseInFile(path);
					s_logger.debug("Opened database file {}", path);
				} catch (ConfigurationException e1) {
					s_logger.debug("Database error: {}", e1.getMessage());
				}
				frame.setVisible(false);
			}
		});
        frame.getContentPane().add(cancelButton, "5, 16, left, default");
        
        cancelButton.addActionListener(new ActionListener()  {
			@Override
			public void actionPerformed(ActionEvent e) {
				s_logger.debug("Cancel override OIDS action performed");
				frame.setVisible(false);
			}
		});
        frame.setVisible(true);		
	}
	public ShowOidDialogAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
		m_frame.setVisible(true);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
        final JFrame frame = new JFrame();
        s_logger.debug("ShowOidDialogAction.actionPerformed()");
        if (!m_frame.isVisible()) m_frame.setVisible(true);
	}
}
