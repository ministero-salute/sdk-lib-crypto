/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.utils;

import org.apache.commons.lang3.StringUtils;

/**
 * @author alessandro.imperio
 *
 */
public class LogUtil {
	
	private static final boolean	VERBOSE_LOGGING		= Boolean.valueOf(LibProperties.getConfigurationProperty("verbose.logging"));
	private static final int		LOG_STRING_LIMIT	= Integer.valueOf(LibProperties.getConfigurationProperty("log.string.limit"));
	
	public static String formatStringForLogging(String content) {
		
		return (VERBOSE_LOGGING)
				? content
				: StringUtils.abbreviate(	content,
											"...",
											LOG_STRING_LIMIT);
	}
}