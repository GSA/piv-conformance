/*
 * Copyright 2015-2018 the original author or authors.
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v2.0 which
 * accompanies this distribution and is available at
 *
 * http://www.eclipse.org/legal/epl-v20.html
 */

package gov.gsa.pivconformance.conformancelib.tools.junitconsole;

import java.io.PrintWriter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.reporting.ReportEntry;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

import gov.gsa.pivconformance.conformancelib.junitoptions.Theme;

/**
 * @since 1.0
 */
class TreePrintingListener implements TestExecutionListener {

	private final Map<String, TreeNode> nodesByUniqueId = new ConcurrentHashMap<>();
	private TreeNode root;
	private final TreePrinter treePrinter;

	TreePrintingListener(PrintWriter out, boolean disableAnsiColors, Theme theme) {
		this.treePrinter = new TreePrinter(out, theme, disableAnsiColors);
	}

	private TreeNode addNode(TestIdentifier testIdentifier, Supplier<TreeNode> nodeSupplier) {
		TreeNode node = nodeSupplier.get();
		nodesByUniqueId.put(testIdentifier.getUniqueId(), node);
		testIdentifier.getParentId().map(nodesByUniqueId::get).orElse(root).addChild(node);
		return node;
	}

	private TreeNode getNode(TestIdentifier testIdentifier) {
		return nodesByUniqueId.get(testIdentifier.getUniqueId());
	}

	@Override
	public void testPlanExecutionStarted(TestPlan testPlan) {
		root = new TreeNode(testPlan.toString());
	}

	@Override
	public void testPlanExecutionFinished(TestPlan testPlan) {
		treePrinter.print(root);
	}

	@Override
	public void executionStarted(TestIdentifier testIdentifier) {
		addNode(testIdentifier, () -> new TreeNode(testIdentifier));
	}

	@Override
	public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
		getNode(testIdentifier).setResult(testExecutionResult);
	}

	@Override
	public void executionSkipped(TestIdentifier testIdentifier, String reason) {
		addNode(testIdentifier, () -> new TreeNode(testIdentifier, reason));
	}

	@Override
	public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {
		getNode(testIdentifier).addReportEntry(entry);
	}

}
