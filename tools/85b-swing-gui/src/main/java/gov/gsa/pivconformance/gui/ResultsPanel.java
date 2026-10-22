package gov.gsa.pivconformance.gui;

import gov.gsa.pivconformance.conformancelib.configuration.TestStatus;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.LineBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.Locale;

/** Native, read-only view of one completed CCT run. It never reads the card. */
final class ResultsPanel extends JPanel {
    private static final Color BLUE = CctUi.BLUE, INK = CctUi.INK, MUTED = CctUi.MUTED,
            BACKGROUND = CctUi.CANVAS, LINE = new Color(0xe4e7ec), GREEN = new Color(0x067647),
            RED = new Color(0xb42318), AMBER = new Color(0x936200);
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("MMM d, yyyy h:mm a z")
            .withZone(ZoneId.systemDefault());
    enum Filter {
        ATTENTION("Needs attention"), FAILED("Fail"), UNSUPPORTED("Unsupported"), ALL("All cases"), PASSED("Pass");
        private final String label;
        Filter(String label) { this.label = label; }
        @Override public String toString() { return label; }
        boolean includes(RunResults.CaseResult c) {
            return switch (this) {
                case ATTENTION -> c.status() != TestStatus.PASS || c.expectationMismatch();
                case FAILED -> c.status() == TestStatus.FAIL;
                case UNSUPPORTED -> c.status() == TestStatus.SKIP;
                case ALL -> true;
                case PASSED -> c.status() == TestStatus.PASS;
            };
        }
    }

    private CompletedTestRun run;
    private final JTextArea metadata = text("No completed run", 13, MUTED);
    private final JTextArea executionIssue = text("", 13, RED);
    private final JPanel counts = panel(new GridLayout(1, 4, 12, 0), BACKGROUND);
    private final JComboBox<Filter> filter = new JComboBox<>(Filter.values());
    private final JTextField search = new JTextField();
    private final DefaultListModel<RunResults.CaseResult> visible = new DefaultListModel<>();
    private final JList<RunResults.CaseResult> cases = new JList<>(visible) {
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
    };
    private final JLabel listCount = label("", 12, Font.PLAIN, MUTED);
    private final JPanel detail = panel(new BorderLayout(), Color.WHITE);
    private final JButton openCsv = button("Open CSV", false);

    ResultsPanel(Action packageResults, Runnable backToTesting) {
        super(new BorderLayout());
        setBackground(BACKGROUND);
        setBorder(inset(18, 22, 12, 22));
        JPanel heading = panel(new BorderLayout(12, 0), BACKGROUND);
        JPanel title = panel(new GridLayout(0, 1, 0, 5), BACKGROUND);
        title.add(label("CARD CONFORMANCE TOOL / RESULTS", 11, Font.BOLD, BLUE));
        title.add(label("Test results", 28, Font.BOLD, INK));
        metadata.setRows(2);
        metadata.setColumns(45);
        metadata.getAccessibleContext().setAccessibleName("Run identity and completion time");
        title.add(metadata);
        heading.add(title, BorderLayout.CENTER);
        JPanel actions = panel(new FlowLayout(FlowLayout.RIGHT, 8, 8), BACKGROUND);
        JButton back = button("Back to Testing", false);
        back.addActionListener(e -> backToTesting.run());
        openCsv.addActionListener(e -> { if (run != null) openFile(run.csvPath()); });
        JButton pack = CctUi.button(packageResults, "Package Results", true);
        actions.add(back);
        actions.add(openCsv);
        actions.add(pack);
        heading.add(actions, BorderLayout.EAST);
        counts.setBorder(inset(16, 0, 12, 0));
        JPanel overview = panel(new BorderLayout(), BACKGROUND);
        overview.add(heading, BorderLayout.NORTH);
        overview.add(counts, BorderLayout.CENTER);
        JPanel runStatus = panel(new BorderLayout(0, 8), BACKGROUND);
        executionIssue.getAccessibleContext().setAccessibleName("Run execution issue");
        runStatus.add(executionIssue, BorderLayout.CENTER);
        overview.add(runStatus, BorderLayout.SOUTH);
        overview.setBorder(inset(0, 0, 16, 0));
        add(overview, BorderLayout.NORTH);

        JPanel navigator = panel(new BorderLayout(), Color.WHITE);
        navigator.setBorder(new LineBorder(LINE));
        JPanel controls = panel(new BorderLayout(0, 10), Color.WHITE);
        controls.setBorder(inset(14, 14, 12, 14));
        controls.add(label("Findings", 17, Font.BOLD, INK), BorderLayout.NORTH);
        JPanel fields = panel(new GridLayout(0, 1, 0, 8), Color.WHITE);
        filter.getAccessibleContext().setAccessibleName("Filter results");
        search.putClientProperty("JTextField.placeholderText", "Search case or object (optional)");
        search.setToolTipText("Optional: narrow the list by case number, object or recorded reason.");
        search.getAccessibleContext().setAccessibleName("Search results (optional)");
        search.setPreferredSize(new Dimension(240, 34));
        fields.add(filter);
        fields.add(search);
        controls.add(fields, BorderLayout.CENTER);
        controls.add(listCount, BorderLayout.SOUTH);
        navigator.add(controls, BorderLayout.NORTH);
        cases.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        cases.setFixedCellHeight(Math.round(94 * fontScale()));
        cases.setCellRenderer(new CaseRenderer());
        cases.getAccessibleContext().setAccessibleName("Result cases");
        JScrollPane caseScroll = new JScrollPane(cases);
        caseScroll.setBorder(null);
        caseScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        navigator.add(caseScroll, BorderLayout.CENTER);
        navigator.setMinimumSize(new Dimension(270, 120));
        detail.setBorder(new LineBorder(LINE));
        detail.setMinimumSize(new Dimension(340, 120));
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, navigator, detail);
        split.setBorder(null);
        split.setDividerSize(10);
        split.setResizeWeight(0.30);
        split.setDividerLocation(310);
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
        filter.addActionListener(e -> refresh());
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refresh(); }
            public void removeUpdate(DocumentEvent e) { refresh(); }
            public void changedUpdate(DocumentEvent e) { refresh(); }
        });
        cases.addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showDetail(cases.getSelectedValue()); });
        getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F,
                GraphicsEnvironment.isHeadless() ? java.awt.event.InputEvent.CTRL_DOWN_MASK
                        : Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()), "find");
        getActionMap().put("find", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { search.requestFocusInWindow(); search.selectAll(); }
        });
        setCompletedRun(null);
    }

    void setCompletedRun(CompletedTestRun value) {
        run = value;
        search.setText("");
        filter.setSelectedItem(Filter.ATTENTION);
        RunResults results = value == null ? null : value.getResults();
        metadata.setText(results == null ? "No completed run" : results.database().getFileName() + " · "
                + (results.complete() ? "Completed " : "Incomplete · ") + TIME.format(results.finished()) + " · "
                + results.duration().toSeconds() / 60 + "m " + results.duration().toSeconds() % 60 + "s");
        counts.removeAll();
        counts.add(countCard("Cases processed", results == null ? 0 : results.cases().size(), INK, Filter.ALL));
        counts.add(countCard("Pass", results == null ? 0 : results.passed(), GREEN, Filter.PASSED));
        counts.add(countCard("Fail", results == null ? 0 : results.failed(), RED, Filter.FAILED));
        counts.add(countCard("Unsupported", results == null ? 0 : results.unsupported(), AMBER, Filter.UNSUPPORTED));
        boolean empty = results == null || results.cases().isEmpty();
        executionIssue.setText(results == null || results.complete() ? "" : "This run did not complete."
                + (results.executionIssue().isBlank() ? "" : " " + results.executionIssue()));
        executionIssue.setVisible(!executionIssue.getText().isBlank());
        openCsv.setEnabled(results != null);
        filter.setEnabled(!empty);
        search.setEnabled(!empty);
        refresh();
        counts.revalidate();
        counts.repaint();
    }

    private JButton countCard(String title, long count, Color color, Filter selection) {
        JButton card = new JButton();
        card.setLayout(new BorderLayout(0, 4));
        card.setBorder(new CompoundBorder(new LineBorder(LINE), inset(12, 16, 12, 16)));
        card.setBackground(Color.WHITE);
        card.add(label(title, 13, Font.PLAIN, MUTED), BorderLayout.NORTH);
        card.add(label(Long.toString(count), 30, Font.BOLD, color), BorderLayout.CENTER);
        card.getAccessibleContext().setAccessibleName(title + ": " + count);
        card.setToolTipText("Show " + selection.toString().toLowerCase(Locale.ROOT));
        card.addActionListener(e -> filter.setSelectedItem(selection));
        return card;
    }

    private void refresh() {
        RunResults.CaseResult selected = cases.getSelectedValue();
        visible.clear();
        RunResults results = run == null ? null : run.getResults();
        if (results != null) {
            String query = search.getText().strip().toLowerCase(Locale.ROOT);
            Filter mode = (Filter) filter.getSelectedItem();
            results.cases().stream().filter(mode::includes).filter(c -> c.searchText().contains(query))
                    .sorted(Comparator.comparingInt(RunResults.CaseResult::attentionOrder))
                    .forEach(visible::addElement);
        }
        listCount.setText(visible.size() + " shown · " + (results == null ? 0 : results.cases().size()) + " cases in run");
        if (selected != null && visible.contains(selected)) cases.setSelectedValue(selected, true);
        else if (!visible.isEmpty()) cases.setSelectedIndex(0);
        else showDetail(null);
    }

    private void showDetail(RunResults.CaseResult result) {
        detail.removeAll();
        ScrollBody body = new ScrollBody();
        body.setBorder(inset(20, 24, 20, 24));
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0; g.gridy = 0; g.weightx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.anchor = GridBagConstraints.NORTHWEST;
        g.insets = new Insets(0, 0, 14, 0);
        if (result == null) {
            boolean noResults = run == null || run.getResults() == null || run.getResults().cases().isEmpty();
            boolean noAttention = !noResults && run.getResults().cases().stream().noneMatch(Filter.ATTENTION::includes);
            add(body, g, label(noResults ? "No completed results" : noAttention ? "No failures recorded" : "No matching cases", 22, Font.BOLD, INK));
            add(body, g, text(noResults ? "No case outcomes were recorded. Review the run status and selected profile."
                    : "Choose All cases to inspect the compact case list, or change the filter/search.", 14, MUTED));
        } else {
            Color statusColor = result.status() == TestStatus.SKIP ? AMBER : result.status() == TestStatus.FAIL ? RED : GREEN;
            add(body, g, label(result.statusText() + "  ·  CASE " + result.id(), 13, Font.BOLD, statusColor));
            JTextArea title = text(result.description(), 20, INK);
            title.setFont(font(20, Font.BOLD));
            add(body, g, title);
            add(body, g, label(result.object(), 13, Font.PLAIN, MUTED));
            String expectation = "Expected " + (result.expectedPass() ? "Pass" : "Fail") + " · Actual " + result.statusText();
            if (result.executionError()) expectation += "\nCCT recorded an execution error; review its recorded cause below.";
            else if (result.expectationMismatch()) expectation += "\nThe actual result differs from the selected profile's expectation.";
            add(body, g, section("Profile expectation", expectation));
            if (result.status() == TestStatus.PASS && !result.expectationMismatch()) {
                add(body, g, section("Result", "The case completed without a recorded assertion failure. Detailed findings are shown for cases needing attention."));
            } else {
                String explanation = result.steps().stream().filter(s -> s.status() != TestStatus.PASS)
                        .map(RunResults.StepResult::explanation).distinct().collect(java.util.stream.Collectors.joining("\n\n"));
                add(body, g, section("What happened", explanation.isBlank()
                        ? "No assertion failure was recorded. Compare the actual outcome with the profile expectation." : explanation));
                for (RunResults.StepResult step : result.steps()) {
                    if (step.status() == TestStatus.PASS || step.booleanExpectation()) continue;
                    if (!step.expected().isBlank()) add(body, g, section("Expected value", step.expected()));
                    if (!step.actual().isBlank()) add(body, g, section("Observed value", step.actual()));
                }
                result.steps().stream().filter(s -> s.status() != TestStatus.PASS)
                        .flatMap(s -> s.references().stream()).distinct().forEach(ref -> add(body, g, referenceCard(ref)));
                if (result.steps().isEmpty() || result.steps().stream().anyMatch(s -> s.status() != TestStatus.PASS && s.references().isEmpty()))
                    add(body, g, section("Source reference", "A source reference is missing for one or more steps. Technical evidence lists the test methods."));
                add(body, g, section("What to check", result.guidance()));
                StringBuilder evidence = new StringBuilder();
                for (RunResults.StepResult step : result.steps()) {
                    if (step.status() == TestStatus.PASS) continue;
                    evidence.append(step.method()).append("\n").append(step.technical()).append("\n\n");
                }
                add(body, g, disclosure("Technical evidence", evidence.toString()));
                JPanel actions = panel(new FlowLayout(FlowLayout.LEFT, 8, 0), Color.WHITE);
                JButton copy = button("Copy finding", false);
                copy.addActionListener(e -> copy(result.id() + ": " + result.statusText() + "\n" + result.description()
                        + "\n" + result.reason() + "\n" + result.guidance() + "\n\n"
                        + result.steps().stream().filter(s -> s.status() != TestStatus.PASS)
                            .flatMap(s -> s.references().stream()).distinct().map(RunResults.Reference::text)
                            .collect(java.util.stream.Collectors.joining("\n\n"))));
                JButton logs = button("Open run debug log", false);
                logs.addActionListener(e -> openFile(run.getResultsDirectory().resolve("logs/debug")
                        .resolve(run.getTimeStampPrefix() + "-debug.log")));
                actions.add(copy); actions.add(logs);
                add(body, g, actions);
            }
        }
        g.weighty = 1;
        body.add(Box.createVerticalGlue(), g);
        JScrollPane scroll = new JScrollPane(body);
        scroll.setBorder(null);
        scroll.getViewport().setBackground(Color.WHITE);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        detail.add(scroll);
        detail.revalidate(); detail.repaint();
    }

    private JPanel referenceCard(RunResults.Reference ref) {
        Color background = new Color(0xf0f6fb);
        JPanel p = panel(new BorderLayout(0, 12), background);
        p.setBorder(new CompoundBorder(new LineBorder(new Color(0xd9e7f2)), inset(14, 14, 14, 14)));
        p.add(label("Standard reference", 13, Font.BOLD, BLUE), BorderLayout.NORTH);
        JPanel content = panel(new GridBagLayout(), background);
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0; g.gridy = 0; g.weightx = 1; g.fill = GridBagConstraints.HORIZONTAL;
        g.anchor = GridBagConstraints.NORTHWEST; g.insets = new Insets(0, 0, 8, 0);
        add(content, g, label(ref.publication(), 14, Font.BOLD, INK));
        add(content, g, text(ref.location(), 12, MUTED));
        if (!ref.excerpt().isBlank()) {
            JPanel quotation = panel(new BorderLayout(0, 7), Color.WHITE);
            quotation.setBorder(new CompoundBorder(BorderFactory.createMatteBorder(0, 3, 0, 0, BLUE), inset(10, 12, 10, 12)));
            quotation.add(label("Official wording (excerpt)", 12, Font.BOLD, BLUE), BorderLayout.NORTH);
            JTextArea words = text("“" + ref.excerpt() + "”", 14, INK);
            words.setFont(font(14, Font.ITALIC));
            quotation.add(words, BorderLayout.CENTER);
            add(content, g, quotation);
        }
        add(content, g, label("What CCT checks", 12, Font.BOLD, BLUE));
        add(content, g, text(ref.scope(), 14, INK));
        p.add(content, BorderLayout.CENTER);
        JButton open = button(ref.documentUrl().isBlank() ? "Open official publication ↗" : "Open cited page ↗", false);
        open.setToolTipText(ref.link());
        open.addActionListener(e -> openReference(ref.link()));
        JPanel actions = panel(new FlowLayout(FlowLayout.LEFT, 0, 0), background);
        actions.add(open);
        p.add(actions, BorderLayout.SOUTH);
        return p;
    }

    private static JPanel disclosure(String title, String content) {
        JPanel p = panel(new BorderLayout(0, 8), Color.WHITE);
        JToggleButton toggle = new JToggleButton(title + " ▸");
        CctUi.styleButton(toggle, false);
        toggle.setHorizontalAlignment(SwingConstants.LEFT);
        JTextArea evidence = text(content, 12, MUTED);
        evidence.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        evidence.setVisible(false);
        toggle.addActionListener(e -> {
            evidence.setVisible(toggle.isSelected());
            toggle.setText(title + (toggle.isSelected() ? " ▾" : " ▸"));
            p.revalidate();
        });
        p.add(toggle, BorderLayout.NORTH);
        p.add(evidence, BorderLayout.CENTER);
        return p;
    }

    private void openFile(Path path) {
        try {
            if (!Files.isRegularFile(path)) throw new java.io.IOException("This run's file is unavailable: " + path);
            if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.OPEN))
                throw new java.io.IOException("Opening files is unavailable. File: " + path);
            Desktop.getDesktop().open(path.toFile());
        } catch (Exception e) { showError(e.getMessage()); }
    }

    private void openReference(String url) {
        try {
            URI uri = URI.create(url);
            if (!"https".equalsIgnoreCase(uri.getScheme())) throw new IllegalArgumentException("Only HTTPS source links are supported.");
            if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE))
                throw new java.io.IOException("Open this source in your browser: " + url);
            Desktop.getDesktop().browse(uri);
        } catch (Exception e) { showError(e.getMessage()); }
    }

    private void copy(String content) {
        try { Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(content), null); }
        catch (RuntimeException e) { showError("Unable to copy the finding: " + e.getMessage()); }
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, text(message, 14, INK), "Results", JOptionPane.ERROR_MESSAGE);
    }

    // Tests use these methods to filter and select cases without a desktop.
    void selectFilter(Filter mode) { filter.setSelectedItem(mode); }
    void search(String query) { search.setText(query); }
    int visibleCount() { return visible.size(); }
    RunResults.CaseResult selectedCase() { return cases.getSelectedValue(); }

    private static void add(JPanel panel, GridBagConstraints g, Component child) { panel.add(child, g); g.gridy++; }
    private static JPanel section(String heading, String content) {
        JPanel p = panel(new BorderLayout(0, 7), Color.WHITE);
        p.add(label(heading, 13, Font.BOLD, INK), BorderLayout.NORTH);
        p.add(text(content, 14, MUTED), BorderLayout.CENTER);
        return p;
    }
    private static float fontScale() { return CctUi.fontScale(); }
    private static Font font(float size, int style) { return CctUi.font(size, style); }
    private static JLabel label(String s, float size, int style, Color color) {
        JLabel l = new JLabel(); l.putClientProperty("html.disable", Boolean.TRUE); l.setText(s);
        l.setFont(font(size, style)); l.setForeground(color); return l;
    }
    private static JPanel panel(LayoutManager layout, Color color) {
        JPanel p = new JPanel(layout); p.setBackground(color); return p;
    }
    private static javax.swing.border.Border inset(int t, int l, int b, int r) { return BorderFactory.createEmptyBorder(t, l, b, r); }
    private static JTextArea text(String s, int size, Color color) {
        JTextArea a = new JTextArea(s); a.setFont(font(size, Font.PLAIN)); a.setForeground(color);
        a.setLineWrap(true); a.setWrapStyleWord(true); a.setEditable(false); a.setOpaque(false); a.setBorder(null); return a;
    }
    private static JButton button(String s, boolean primary) {
        return CctUi.button(s, primary);
    }
    private static String concise(String value, int length) { return value.length() <= length ? value : value.substring(0, length - 1) + "…"; }

    private static final class CaseRenderer extends JPanel implements ListCellRenderer<RunResults.CaseResult> {
        CaseRenderer() { super(new BorderLayout(0, 6)); }
        @Override public Component getListCellRendererComponent(JList<? extends RunResults.CaseResult> list,
                RunResults.CaseResult c, int index, boolean selected, boolean focused) {
            removeAll();
            Color background = selected ? new Color(0xeaf2fa) : Color.WHITE;
            setBackground(background);
            setBorder(new CompoundBorder(BorderFactory.createMatteBorder(0, selected ? 3 : 0, 1, 0, selected ? BLUE : LINE),
                    inset(12, selected ? 11 : 14, 10, 12)));
            JPanel top = panel(new BorderLayout(), background);
            top.add(label(c.id(), 12, Font.BOLD, selected ? BLUE : MUTED), BorderLayout.WEST);
            top.add(label(c.statusText(), 11, Font.BOLD, c.status() == TestStatus.SKIP ? AMBER
                    : c.status() == TestStatus.PASS ? GREEN : RED), BorderLayout.EAST);
            add(top, BorderLayout.NORTH);
            add(label(concise(c.description(), 65), 13, Font.BOLD, INK), BorderLayout.CENTER);
            add(label(concise(c.object(), 48), 11, Font.PLAIN, MUTED), BorderLayout.SOUTH);
            getAccessibleContext().setAccessibleName(c.id() + " " + c.statusText() + " " + c.description());
            return this;
        }
        @Override public void paint(Graphics g) { layoutChildren(this); super.paint(g); }
    }

    private static void layoutChildren(Container container) {
        container.doLayout();
        for (Component child : container.getComponents()) if (child instanceof Container c) layoutChildren(c);
    }
    private static final class ScrollBody extends JPanel implements Scrollable {
        ScrollBody() { super(new GridBagLayout()); setBackground(Color.WHITE); }
        public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        public int getScrollableUnitIncrement(Rectangle r, int orientation, int direction) { return 16; }
        public int getScrollableBlockIncrement(Rectangle r, int orientation, int direction) { return Math.max(16, r.height - 32); }
        public boolean getScrollableTracksViewportWidth() { return true; }
        public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
