package gov.gsa.pivconformancegui;

import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.CardInfoController;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class UtilitiesPane extends JPanel {
	private static final Logger s_logger = LoggerFactory.getLogger(UtilitiesPane.class);
	public UtilitiesPane() {
		
		JButton btnRunTest = new JButton("Run Test");
		btnRunTest.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				s_logger.error("Running test...");
				byte[] atr = CardInfoController.getATR();
				String atrString = Hex.encodeHexString(atr);
				s_logger.info("Card ATR: {}", atrString);
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
