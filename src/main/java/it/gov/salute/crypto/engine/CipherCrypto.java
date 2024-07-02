/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.engine;

import javax.crypto.Cipher;

import it.gov.salute.crypto.utils.CryptoUtil;
import it.gov.salute.crypto.utils.LibProperties;

/**
 * @author alessandro.imperio
 *
 */
public abstract class CipherCrypto {
	
	public abstract String getAlgorithm();
	
	// optional - default to null
	public String getCipherMode() {
		
		return null;
	}
	
	// optional - default to null
	public String getCipherPaddingType() {
		
		return null;
	}
	
	public abstract Cipher getCipher();
	
	public String getCipherAlgorithm() {
		
		return CryptoUtil.generateCipherTransformationString(	this.getAlgorithm(),
																this.getCipherMode(),
																this.getCipherPaddingType());
	}
	
	public int getCipherBlockSize() {
		
		if (this.getCipher() != null) {
			
			return this.getCipher().getBlockSize();
		}
		else {
			
			throw new RuntimeException(LibProperties.getMessageProperty("errore.determinazione.dimensione.blocchi.cifratore",
																		this.getAlgorithm()));
		}
	}
	
}
