package gov.gsa.pivconformancegui;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;

public class GuiRunner {
    private static void createAndShow() {
        JFrame mainFrame = new JFrame("PIV Conformance Tester");
        mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JLabel tempLabel = new JLabel("PIV Conformance Test Runner");
        mainFrame.getContentPane().add(tempLabel);

        mainFrame.pack();
        mainFrame.setVisible(true);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    createAndShow();
                }
            }
            );

    }
}
