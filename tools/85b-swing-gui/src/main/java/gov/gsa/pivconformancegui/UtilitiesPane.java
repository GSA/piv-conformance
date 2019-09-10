package gov.gsa.pivconformancegui;

import javax.swing.JPanel;
import gov.gsa.pivconformance.card.client.*;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.CardInfoController;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.ConnectionDescription;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;

import javax.swing.JButton;
import java.awt.event.ActionListener;

import java.awt.event.ActionEvent;

public class UtilitiesPane extends JPanel {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final Logger s_logger = LoggerFactory.getLogger(UtilitiesPane.class);
	public UtilitiesPane() {
		
		JButton btnRunTest = new JButton("Run Test");
		btnRunTest.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				s_logger.error("Running test...");
				byte[] atr = CardInfoController.getATR();
				String atrString = Hex.encodeHexString(atr);
				s_logger.info("Card ATR: {}", atrString);
				//Security.insertProviderAt(new SmartcardioProvider(), 1);
				/*Provider[] providers = Security.getProviders();
				for(Provider p : providers) {
					s_logger.error("Provider: {}", p.getName());
				}
				//Security.insertProviderAt(new SmartcardioProvider(), 1);
				providers = Security.getProviders();
				for(Provider p : providers) {
					s_logger.error("Provider: {}", p.getName());
				}
				*/
				//2.16.840.1.101.3.7.2.96.48
				CardSettingsSingleton css = CardSettingsSingleton.getInstance();

				ConnectionDescription cd = ConnectionDescription.createFromTerminal(css.getTerminal());
				try {
					if(!css.getTerminal().isCardPresent()) {
						s_logger.error("No card is present in {}", css.getTerminal().getName());
					}
				}catch(Exception e2) {
					s_logger.error("caught exception", e2);
				}
				CardHandle ch = new CardHandle();
				MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
				DefaultPIVApplication piv = new DefaultPIVApplication();
				ApplicationAID aid  = new ApplicationAID();
				ApplicationProperties cardAppProperties = new ApplicationProperties();
				result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
				PIVAuthenticators authenticators = new PIVAuthenticators();
				//authenticators.addApplicationPin(css.getApplicationPin());
				authenticators.addApplicationPin("123456");
				result = piv.pivLogIntoCardApplication(ch, authenticators.getBytes());
				//2.16.840.1.101.3.7.2.96.48
				PIVDataObject obj =
						PIVDataObjectFactory.createDataObjectForOid(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID);
				result = piv.pivGetData(ch, APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID, obj);
				s_logger.error("pivGetData returned {}", result);

			}
		});
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(Alignment.TRAILING, groupLayout.createSequentialGroup()
					.addContainerGap(170, Short.MAX_VALUE)
					.addComponent(btnRunTest)
					.addGap(166))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(32)
					.addComponent(btnRunTest)
					.addContainerGap(243, Short.MAX_VALUE))
		);
		setLayout(groupLayout);
	}
}
