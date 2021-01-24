package gov.gsa.pivconformance.gui;

import java.awt.Color;

import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;
import gov.gsa.pivconformance.conformancelib.utilities.TimeStampedFileAppender;

public class GuiDebugAppender extends TimeStampedFileAppender<ILoggingEvent> {
	
	private final PatternLayout m_pattern;
	private static final SimpleAttributeSet s_errorAttributes;
	private static final SimpleAttributeSet s_warningAttributes;
	private static final SimpleAttributeSet s_infoAttributes;
	private static final SimpleAttributeSet s_otherAttributes;
	
	static {
		s_errorAttributes = new SimpleAttributeSet();
		s_errorAttributes.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		s_errorAttributes.addAttribute(StyleConstants.Foreground, Color.RED);
		s_warningAttributes = new SimpleAttributeSet();
		s_warningAttributes.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		s_warningAttributes.addAttribute(StyleConstants.Foreground, Color.ORANGE);
		s_infoAttributes = new SimpleAttributeSet();
		s_infoAttributes.addAttribute(StyleConstants.Foreground, Color.BLACK);
		s_otherAttributes = new SimpleAttributeSet();
		s_otherAttributes.addAttribute(StyleConstants.Foreground, Color.GRAY);
		s_otherAttributes.addAttribute(StyleConstants.Italic, Boolean.TRUE);
	}
	
	public GuiDebugAppender(String pattern) {
		m_pattern = new PatternLayout();
		m_pattern.setPattern(pattern);
	}

	@Override
	public void start() {
		m_pattern.setContext(getContext());
		m_pattern.start();
		super.start();
	}

	@Override
	protected void append(ILoggingEvent eventObject) {
		GuiRunnerApplication app = GuiRunnerAppController.getInstance().getApp();
		//if(!app.isDebugPaneVisible()) return;
		String formattedMessage = m_pattern.doLayout(eventObject);
		SwingUtilities.invokeLater(() -> {
			JTextPane target = app.getDebugFrame().getDebugTextPane();
			try {
				if(eventObject.getLevel() == Level.ERROR) {
					target.getDocument().insertString(target.getDocument().getLength(), formattedMessage, s_errorAttributes);
				} else if(eventObject.getLevel() == Level.WARN) {
					target.getDocument().insertString(target.getDocument().getLength(), formattedMessage, s_warningAttributes);
				} else if(eventObject.getLevel() == Level.INFO) {
					target.getDocument().insertString(target.getDocument().getLength(), formattedMessage, s_infoAttributes);
				} else {
					target.getDocument().insertString(target.getDocument().getLength(), formattedMessage, s_otherAttributes);
				}
				target.setCaretPosition(target.getDocument().getLength());
			} catch(BadLocationException e) {
				// if this ever happens, there's nothing we can do
			}
		});
	}

}
