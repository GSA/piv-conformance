package gov.gsa.pivconformance.gui;

import javax.swing.AbstractButton;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Font;
import java.awt.Insets;

import static com.formdev.flatlaf.FlatClientProperties.MINIMUM_HEIGHT;

/** Shared presentation for the testing workspace, results workspace and package dialog. */
final class CctUi {
    static final Color CANVAS = new Color(0xf5f7fa);
    static final Color BLUE = new Color(0x024d86);
    static final Color INK = new Color(0x18212f);
    static final Color MUTED = new Color(0x667085);

    private CctUi() { }

    static float fontScale() { return Math.max(1f, UIManager.getFont("Label.font").getSize2D() / 13f); }
    static Font font(float size, int style) {
        return UIManager.getFont("Label.font").deriveFont(style, size * fontScale());
    }

    static JButton button(String text, boolean primary) {
        JButton button = new JButton(text);
        styleButton(button, primary);
        return button;
    }

    static JButton button(Action action, String text, boolean primary) {
        JButton button = new JButton(action);
        button.setText(text);
        button.setIcon(null);
        styleButton(button, primary);
        return button;
    }

    static void styleButton(AbstractButton button, boolean primary) {
        button.setFont(font(13, Font.PLAIN));
        button.setMargin(new Insets(8, 12, 8, 12));
        button.putClientProperty(MINIMUM_HEIGHT, 36);
        button.setBackground(primary ? BLUE : Color.WHITE);
        button.setForeground(primary ? Color.WHITE : INK);
    }
}
