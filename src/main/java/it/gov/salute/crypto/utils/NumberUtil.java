/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.utils;

/**
 * @author alessandro.imperio
 *
 */
public class NumberUtil {
	
	/**
	 * determina il primo multiplo di n direttamente successivo al numero specificato
	 * 
	 * @param number
	 * @param n
	 * @return
	 */
	public static int calcolaProssimoMultiplo(	int number,
												int n) {
		
		int mod = number % n;
		int complement = n - mod;
		return number + complement;
	}
}
