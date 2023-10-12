package it.gov.salute.crypto.beans;

import java.util.Arrays;
import java.util.List;

import it.gov.salute.crypto.constants.CipherAlgorithms;

/**
 * @author alessandro.imperio
 *
 */
public enum CipherPropertiesEnum {
	
	AES("AES",
			CipherAlgorithms.AES,
			Arrays.asList(	128,
							192,
							256)),
	RSA("RSA",
			CipherAlgorithms.RSA,
			Arrays.asList(	1024,
							2048));
	
	private final String		name;
	private final String		algorithm;
	private final List<Integer>	keyLengths;
	private final int			defaultKeyLength;
	
	CipherPropertiesEnum(	String name,
							String algorithm,
							List<Integer> keyLengths) {
		
		this.name = name;
		this.algorithm = algorithm;
		this.keyLengths = keyLengths;
		// default to the last element of the List
		this.defaultKeyLength = keyLengths.get(keyLengths.size() - 1);
	}
	
	public String getName() {
		
		return this.name;
	}
	
	public String getAlgorithm() {
		
		return this.algorithm;
	}
	
	public List<Integer> getKeyLengths() {
		
		return this.keyLengths;
	}
	
	public int getDefaultKeyLength() {
		
		return this.defaultKeyLength;
	}
	
}
