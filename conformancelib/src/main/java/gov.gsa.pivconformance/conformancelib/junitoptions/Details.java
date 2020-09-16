/*
 * Copyright 2015-2018 the original author or authors.
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v2.0 which
 * accompanies this distribution and is available at
 *
 * http://www.eclipse.org/legal/epl-v20.html
 */

package gov.gsa.pivconformance.conformancelib.junitoptions;

import static org.apiguardian.api.API.Status.INTERNAL;

import org.apiguardian.api.API;

/**
 * @since 1.0
 */
@API(status = INTERNAL, since = "1.0")
public enum Details {

	/**
	 * No test plan execution details are printed.
	 */
	NONE,

	/**
	 * Print summary table of counts only.
	 */
	SUMMARY,

	/**
	 * Test plan execution details are rendered in a flat, line-by-line mode.
	 */
	FLAT,

	/**
	 * Test plan execution details are rendered as a simple tree.
	 */
	TREE,

	/**
	 * Combines {@link #TREE} and {@link #FLAT} modes.
	 */
	VERBOSE;

	/**
	 * Return lower case {@link #name} for easier usage in help text for
	 * available options.
	 */
	@Override
	public String toString() {
		return name().toLowerCase();
	}

}
