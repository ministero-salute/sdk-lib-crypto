package it.gov.salute.crypto.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import it.gov.salute.crypto.constants.Generic;

/**
 * @author alessandro.imperio
 *
 */
public class LibProperties {
	
	private static Logger					logger	= Logger.getLogger(LibProperties.class);
	
	private static Map<String, Properties>	propertiesMap;
	
	/**
	 * @return
	 */
	private static Map<String, Properties> getPropertiesMap() {
		
		if (propertiesMap == null) {
			
			propertiesMap = new HashMap<String, Properties>();
		}
		
		return propertiesMap;
	}
	
	/**
	 * @param filePath
	 * @return
	 * @throws IOException
	 */
	private static Properties getProperties(String filePath) throws IOException {
		
		Properties properties = getPropertiesMap().get(filePath);
		
		if (properties == null) {
			
			InputStream propertiesInputStream = LibProperties.class.getResourceAsStream("/".concat(filePath));
			properties = new Properties();
			properties.load(propertiesInputStream);
			getPropertiesMap().put(	filePath,
									properties);
		}
		
		return properties;
	}
	
	/**
	 * @param name
	 * @return
	 */
	public static String getConfigurationProperty(String name) {
		
		return getProperty(	Generic.CONFIGURATION_PROPERTIES_FILE,
							name);
	}
	
	/**
	 * @param name
	 * @return
	 */
	public static String getMessageProperty(String name) {
		
		return getProperty(	Generic.MESSAGE_PROPERTIES_FILE,
							name);
	}
	
	/**
	 * @param filePath
	 * @param name
	 * @return
	 */
	public static String getProperty(	String filePath,
										String name) {
		
		try {
			
			return getProperties(filePath).getProperty(name);
		}
		catch (IOException e) {
			
			logger.error(	"ERROR",
							e);
			return null;
		}
	}
	
	/**
	 * @param name
	 * @param args
	 * @return
	 */
	public static String getMessageProperty(String name,
											String... args) {
		
		return getProperty(	Generic.MESSAGE_PROPERTIES_FILE,
							name,
							args);
	}
	
	/**
	 * @param filePath
	 * @param name
	 * @param args
	 * @return
	 */
	public static String getProperty(	String filePath,
										String name,
										String... args) {
		
		try {
			
			String property = getProperties(filePath).getProperty(name);
			return completeString(	property,
									args);
		}
		catch (IOException e) {
			
			logger.error(	"ERROR",
							e);
			return null;
		}
	}
	
	/**
	 * @param string
	 * @return
	 */
	private static boolean stringContainsParameters(String string) {
		
		if (StringUtils.isEmpty(string))
			return false;
		
		String expression = "([{][0-9]+[}])+";
		Pattern pattern = Pattern.compile(expression);
		Matcher regexMatcher = pattern.matcher(string);
		return regexMatcher.find();
	}
	
	/**
	 * replace all markers with parameters (if any)
	 * 
	 * @param string
	 * @param parameters
	 * @return
	 */
	private static String completeString(	String string,
											String... parameters) {
		
		if (stringContainsParameters(string)) {
			
			int index = 0;
			for (String parameter : parameters) {
				
				if (parameter != null) {
					
					string = string.replace("{" + index + "}",
											parameter);
				}
				
				index++;
			}
		}
		
		return string;
	}
	
}
