package gov.gsa.pivconformancegui;

import java.awt.Font;
import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;

import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.FormSpecs;
import com.jgoodies.forms.layout.RowSpec;

public class ShowOidDialogAction extends AbstractAction {
	private JTextField pivAuthOverrideTextField;
	private JTextField digitalSignatureOverrideTextField;
	private JTextField keyManagementOverrideTextField;
	private JTextField cardAuthenticationOverrideTextField;
	private JTextField contentSigningOverrideTextField;
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public ShowOidDialogAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
        JFrame frame=new JFrame();
        frame.getContentPane().setBackground(UIManager.getColor("Button.background"));
        frame.setAlwaysOnTop(true);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(376,360);
        frame.setTitle("Certificate Policy OID Overrides");
        frame.getContentPane().setLayout(new FormLayout(new ColumnSpec[] {
        		FormSpecs.RELATED_GAP_COLSPEC,
        		ColumnSpec.decode("left:max(50dlu;min):grow"),
        		ColumnSpec.decode("8dlu"),
        		ColumnSpec.decode("max(135dlu;min):grow"),
        		FormSpecs.RELATED_GAP_COLSPEC,},
        	new RowSpec[] {
        		FormSpecs.RELATED_GAP_ROWSPEC,
        		RowSpec.decode("max(0.8in;min):grow"),
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
        txtDefinitionTextArea.setBackground(UIManager.getColor("Button.background"));
        txtDefinitionTextArea.setEnabled(false);
        txtDefinitionTextArea.setFont(new Font("Tahoma", Font.PLAIN, 11));
        txtDefinitionTextArea.setLineWrap(true);
        txtDefinitionTextArea.setText("This form allows you to override the certificate policy OIDs that the tool checks for each type of certificate.  If your certificates assert different policy OIDs, complete this form to ensure the tool tests for your OIDs.");
        frame.getContentPane().add(txtDefinitionTextArea, "2, 2, 3, 1, fill, fill");
        
        JLabel lblPivAuthentication = new JLabel("PIV Authentication");
        frame.getContentPane().add(lblPivAuthentication, "2, 4, right, default");
        
        pivAuthOverrideTextField = new JTextField();
        frame.getContentPane().add(pivAuthOverrideTextField, "4, 4, fill, default");
        pivAuthOverrideTextField.setColumns(10);
        
        JLabel lblDigitalSignature = new JLabel("Digital Signature");
        frame.getContentPane().add(lblDigitalSignature, "2, 6, right, default");
        
        digitalSignatureOverrideTextField = new JTextField();
        frame.getContentPane().add(digitalSignatureOverrideTextField, "4, 6, fill, default");
        digitalSignatureOverrideTextField.setColumns(10);
        
        JLabel lblKeyManagement = new JLabel("Key Management");
        frame.getContentPane().add(lblKeyManagement, "2, 8, right, default");
        
        keyManagementOverrideTextField = new JTextField();
        frame.getContentPane().add(keyManagementOverrideTextField, "4, 8, fill, default");
        keyManagementOverrideTextField.setColumns(10);
        
        JLabel lblCardAuthentication = new JLabel("Card Authentication");
        frame.getContentPane().add(lblCardAuthentication, "2, 10, right, default");
        
        cardAuthenticationOverrideTextField = new JTextField();
        frame.getContentPane().add(cardAuthenticationOverrideTextField, "4, 10, fill, default");
        cardAuthenticationOverrideTextField.setColumns(10);
        
        JLabel lblContentSigning = new JLabel("Content Signing");
        frame.getContentPane().add(lblContentSigning, "2, 12, right, default");
        
        contentSigningOverrideTextField = new JTextField();
        frame.getContentPane().add(contentSigningOverrideTextField, "4, 12, fill, default");
        contentSigningOverrideTextField.setColumns(10);
        
        JButton saveButton = new JButton("OK");
        frame.getContentPane().add(saveButton, "2, 16, right, default");
        //saveButton.addActionListener(l);
        
        JButton cancelButton = new JButton("Cancel");
        frame.getContentPane().add(cancelButton, "4, 16, left, default");

        frame.setVisible(true);	
	}

}
