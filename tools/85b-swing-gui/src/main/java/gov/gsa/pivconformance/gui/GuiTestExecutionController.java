package gov.gsa.pivconformance.gui;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;

import org.junit.platform.engine.DiscoverySelector;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterProviderSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.TestCaseModel;
import gov.gsa.pivconformance.conformancelib.utilities.TestRunLogController;
import gov.gsa.pivconformance.conformancelib.configuration.TestStepModel;
import gov.gsa.pivconformance.cardlib.utils.PCSCWrapper;
import gov.gsa.pivconformance.cardlib.card.client.CachingDefaultPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.DataModelSingleton;

public class GuiTestExecutionController {
	private static final Logger s_logger = LoggerFactory.getLogger(GuiTestExecutionController.class);
	private static final GuiTestExecutionController INSTANCE = new GuiTestExecutionController();
	private static final String tag30TestId = "8.2.2.1"; // TODO: Fixme

	private TestRunLogController m_trlc;
	private GuiTestTreePanel m_testTreePanel;
	private SimpleTestExecutionPanel m_testExecutionPanel;
	private GuiRunnerToolbar m_toolBar;
	private boolean m_running;
	private LoggerContext m_ctx;

	public static GuiTestExecutionController getInstance() {
		return INSTANCE;
	}
	
	private GuiTestExecutionController() {
		reset();
	}

	private void reset() {
		m_testTreePanel = null;
		m_testExecutionPanel = null;
		m_running = false;
		m_toolBar = null;
		m_trlc = TestRunLogController.getInstance();;
		m_trlc.initialize();
	}

	public GuiTestTreePanel getTestTreePanel() {
		return m_testTreePanel;
	}

	public void setTestTreePanel(GuiTestTreePanel testTreePanel) {
		m_testTreePanel = testTreePanel;
	}

	public SimpleTestExecutionPanel getTestExecutionPanel() {
		return m_testExecutionPanel;
	}

	public void setTestExecutionPanel(SimpleTestExecutionPanel testExecutionPanel) {
		m_testExecutionPanel = testExecutionPanel;
	}
	
	public void setTestRunLogController(TestRunLogController logController) {
		m_trlc = logController;
	}
	
	public TestRunLogController getTestRunLogController() {
		return m_trlc;
	}

	public void setToolBar(GuiRunnerToolbar toolBar) {
		m_toolBar = toolBar;
	}

	public GuiRunnerToolbar getToolBar() {
		return m_toolBar;
	}

	public boolean isRunning() {
		return m_running;
	}
	
	public LoggerContext getLoggerContext() {
		return m_ctx;
	}
	
	public void setLoggerContext(LoggerContext ctx) {
		m_ctx = ctx;
	}
	
	void runAllTests(GuiTestCaseTreeNode root) {
		
		m_trlc.setStartTimes();
		
		GuiDisplayTestReportAction display = GuiRunnerAppController.getInstance().getDisplayTestReportAction();
		display.setEnabled(false);
		
		s_logger.debug("----------------------------------------");
		s_logger.debug("FIPS 201 CCT " + GuiRunnerAppController.getInstance().getCctVersion());
		s_logger.debug("----------------------------------------");
		
		ConformanceTestDatabase db = GuiRunnerAppController.getInstance().getTestDatabase();
		if(db == null || db.getConnection() == null) {
			s_logger.error("Unable to run tests without a valid database");
			// XXX *** Display message don't just log it
			return;
		}
		m_running = true;
		GuiRunnerAppController.getInstance().reloadTree();
		PCSCWrapper pcsc = PCSCWrapper.getInstance();
		DataModelSingleton.getInstance().reset();

		int atomCount = 0;
		JProgressBar progress = m_testExecutionPanel.getTestProgressBar();
		try {
			SwingUtilities.invokeAndWait(() -> {			
				m_testExecutionPanel.getRunButton().setEnabled(false);
				// TODO: Fix this or else
				m_toolBar.getComponents()[0].setEnabled(false);
				progress.setMaximum(root.getChildCount());
				progress.setValue(0);
				progress.setVisible(true);
				progress.setStringPainted(true);
				progress.setString("");
			});
		} catch (InvocationTargetException | InterruptedException e1) {
			s_logger.error("Unable to launch tests", e1);
			m_running = false;
			return;
		}

		GuiTestListener guiListener = new GuiTestListener();
		guiListener.setProgressBar(progress);

		/* Workaround to ensure that the tool is primed with the CHUID cert.
		 * TODO: Create "factory" database with 8.2.2.1 as the only test, open,
		 * run, then open actual database.
		 */
		
		int passes = 0;
		
		do {
			GuiTestCaseTreeNode curr = (GuiTestCaseTreeNode) root.getFirstChild();

			while(curr != null) {
				TestCaseModel testCase = curr.getTestCase();
				boolean runTest = false;
				String id = testCase.getIdentifier();
				if (passes % 2 == 1) { // TODO: Fixme
					runTest = true;
				} else if (id.compareTo(GuiTestExecutionController.tag30TestId) == 0) {
					runTest = true;
				}
				if (runTest) {
					LauncherDiscoveryRequestBuilder suiteBuilder = LauncherDiscoveryRequestBuilder.request();
					List<DiscoverySelector> discoverySelectors = new ArrayList<>();
					List<TestStepModel> steps = testCase.getSteps();
					for(TestStepModel currentStep : steps) {
						atomCount++;
						Class<?> testClass = null;
						String className = currentStep.getTestClassName();
						String methodName = currentStep.getTestMethodName();
						List<String> parameters = currentStep.getParameters();
						String fqmn = className;
						try {
							testClass = Class.forName(className);
							for(Method m : testClass.getDeclaredMethods()) {
								if(m.getName().contentEquals(methodName)) {
									fqmn += "#" + m.getName() + "(";
									Class<?>[] methodParameters = m.getParameterTypes();
									int nMethodParameters = 0;
									for(Class<?> mp : methodParameters) {
										if(nMethodParameters >= 1) {
											fqmn += ", ";
										}
										fqmn += mp.getName();
										nMethodParameters++;
									}
									fqmn += ")";
								}

							}

							if(fqmn == className) {
								String errorMessage = "Test " + testCase.getIdentifier() + " specifies a test atom " + className + "#" +
										methodName + "()" + " but no such method could be found for the class " + className + "." +
										" (Test atom: " + currentStep.getTestDescription() + ")" +
										" Check that the database matches the included set of test atoms.";

								s_logger.error(errorMessage);
								
								if (passes % 2 == 1) { // TODO: Fixme
									try {
										SwingUtilities.invokeAndWait(() -> {			
											JOptionPane msgBox = new JOptionPane(errorMessage, JOptionPane.ERROR_MESSAGE);
											JDialog dialog = msgBox.createDialog(GuiRunnerAppController.getInstance().getMainFrame(), "Error");
											dialog.setAlwaysOnTop(true);
											dialog.setVisible(true);
										});
									} catch (InvocationTargetException | InterruptedException e) {
										s_logger.error("Unable to display error dialog.");
									}
								}
								break;
							} // End skipped test
						} catch (ClassNotFoundException e) {
							s_logger.error("Method {} was configured in the database but the method could not be found in code.", fqmn);
							break;
						}

						if(className != null && !className.isEmpty() && testClass != null) {
							s_logger.debug("Adding {} from config", fqmn);
							discoverySelectors.add(selectMethod(fqmn));
							ParameterProviderSingleton.getInstance().addNamedParameter(fqmn, parameters);
							String containerName = testCase.getContainer();
							if(containerName != null && !containerName.isEmpty()) {
								ParameterProviderSingleton.getInstance().addContainer(fqmn, containerName);
							}
							s_logger.debug("Added {} from config: {}", fqmn, parameters);
						}

					}
					suiteBuilder.selectors(discoverySelectors);
					suiteBuilder.configurationParameter("TestCaseIdentifier", testCase.getIdentifier());
					LauncherDiscoveryRequest ldr = suiteBuilder.build();
					Launcher l = LauncherFactory.create();
					guiListener.setTestCaseIdentifier(testCase.getIdentifier());
					guiListener.setTestCaseDescription(testCase.getDescription());
					guiListener.setTestCaseExpectedResult(testCase.getExpectedStatus() == 1);
					List<TestExecutionListener> listeners = new ArrayList<TestExecutionListener>();
					listeners.add(guiListener);
					registerListeners(l, listeners);
					
					l.execute(ldr);
				}
				curr = (GuiTestCaseTreeNode) curr.getNextSibling();
			}
		} while (++passes < 2); // End of CHUID priming workaround


		try {
			SwingUtilities.invokeAndWait(() -> {
				m_testExecutionPanel.getRunButton().setEnabled(true);
				// TODO: Fix this or else
				m_toolBar.getComponents()[0].setEnabled(true);
			});
		} catch (InvocationTargetException | InterruptedException e) {
			s_logger.error("Failed to enable run button", e);
		}
		
		s_logger.debug("atom count: {}", atomCount);
		s_logger.debug("tree count: {}", root.getChildCount() + root.getLeafCount() );
		s_logger.debug("PCSC counters - connect() was called {} times, transmit() was called {} times",
				pcsc.getConnectCount(), pcsc.getTransmitCount());

		m_trlc.setTimeStamps(); // Sets the timestamp for all of the logger files
		m_trlc.cleanup();
		m_running = false;
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CachingDefaultPIVApplication cpiv = (CachingDefaultPIVApplication) css.getPivHandle();
		cpiv.clearCache();
		display.setEnabled(true);
	}

	private void registerListeners(Launcher l, List<TestExecutionListener> listeners) {
		for(TestExecutionListener listener: listeners) {
			l.registerTestExecutionListeners(listener);
		}
	}

	void runOneTest(GuiTestCaseTreeNode testCase) {

	}

	void runSelectedTests(List<GuiTestCaseTreeNode> testCases) {

	}
}
