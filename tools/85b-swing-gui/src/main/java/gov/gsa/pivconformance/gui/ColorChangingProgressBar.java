package gov.gsa.pivconformance.gui;

import java.awt.Color;

import javax.swing.JProgressBar;
import javax.swing.plaf.basic.BasicProgressBarUI;

public class ColorChangingProgressBar extends JProgressBar {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private ColorChangingProgressBarUi m_ui;
	public ColorChangingProgressBar() {
		m_ui = new ColorChangingProgressBarUi();
		setCurrentUiColor(Color.GREEN);
		setUI(m_ui);
	}
	private void setCurrentUiColor(Color currentColor) {
		m_ui.setCurrentUiColor(currentColor);
	}
	private class ColorChangingProgressBarUi extends BasicProgressBarUI {
		public void setCurrentUiColor(Color currentColor) {
		}
		/*protected Color getSelectionBackground() {
			return m_currentColor;
		}*/
		
	}

}
