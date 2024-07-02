/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.utils;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author alessandro.imperio
 *
 */
public class EncodingUtil {
	
	public static final Charset	DEFAULT_CHARSET	= UTF_8;
	private static final char[]	HEX_CHARS		= "0123456789ABCDEF".toCharArray();
	private static final String	HEX_PREFIX		= "0x";
	public static final char	PADDING_CHAR	= '\0';
	
	/**
	 * @param stringBytes
	 * @return
	 */
	public static String bytesToHexString(byte[] stringBytes) {
		
		char[] chars = new char[2 * stringBytes.length];
		
		for (int i = 0; i < stringBytes.length; i++) {
			
			chars[2 * i] = HEX_CHARS[(stringBytes[i] & 0xF0) >>> 4];
			chars[2 * i + 1] = HEX_CHARS[stringBytes[i] & 0x0F];
		}
		
		return new String(chars);
	}
	
	/**
	 * @param stringBytes
	 * @return
	 */
	public static String bytesToReadableHexString(byte[] stringBytes) {
		
		String hexSequence = bytesToHexString(stringBytes);
		
		StringBuilder stringBuilder = new StringBuilder();
		
		for (int i = 0; i < hexSequence.length(); i += 2) {
			
			if (stringBuilder.length() > 0) {
				
				stringBuilder.append(" ");
			}
			stringBuilder.append(HEX_PREFIX);
			stringBuilder.append(hexSequence.charAt(i));
			stringBuilder.append(hexSequence.charAt(i + 1));
		}
		
		return stringBuilder.toString();
	}
	
	/**
	 * @param hexString
	 * @return
	 */
	public static byte[] hexStringToBytes(String hexString) {
		
		char[] hexChars = hexString.toCharArray();
		int length = hexChars.length / 2;
		byte[] raw = new byte[length];
		
		for (int i = 0; i < length; i++) {
			
			int high = Character.digit(	hexChars[i * 2],
										16);
			int low = Character.digit(	hexChars[i * 2 + 1],
										16);
			int value = (high << 4) | low;
			
			if (value > 127)
				value -= 256;
			
			raw[i] = (byte) value;
		}
		
		return raw;
	}
	
	/**
	 * @param asciiBytes
	 * @return
	 */
	public static String asciiBytesToString(byte[] asciiBytes) {
		
		StringBuilder stringBuilder = new StringBuilder(asciiBytes.length);
		
		for (int i = 0; i < asciiBytes.length; i++) {
			
			stringBuilder.append(Character.toString((char) asciiBytes[i]));
		}
		
		return stringBuilder.toString();
	}
	
	public static int[] bytesToInts(byte[] bytesArray) {
		
		int[] intsArray = new int[bytesArray.length];
		
		for (int i = 0; i < bytesArray.length; i++) {
			
			// unsigned byte to int conversion
			// (& operator to mask off the sign bits)
			intsArray[i] = bytesArray[i] & 0xFF;
		}
		
		return intsArray;
	}
	
	public static String filterBase64String(String string) {
		
		Pattern base64Pattern = Pattern.compile("([A-Za-z0-9/+=])+");
		Matcher base64Matcher = base64Pattern.matcher(string);
		
		StringBuilder stringBuilder = new StringBuilder();
		
		while (base64Matcher.find()) {
			
			stringBuilder.append(base64Matcher.group());
		}
		
		return stringBuilder.toString();
	}
	
}
