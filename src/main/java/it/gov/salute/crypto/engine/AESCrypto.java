/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.engine;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import it.gov.salute.crypto.constants.CipherAlgorithms;
import it.gov.salute.crypto.constants.CipherModes;
import it.gov.salute.crypto.constants.CipherPaddingTypes;
import it.gov.salute.crypto.utils.EncodingUtil;
import it.gov.salute.crypto.utils.LibProperties;
import it.gov.salute.crypto.utils.NumberUtil;

/**
 * @author alessandro.imperio
 *
 */
public class AESCrypto extends CipherCrypto {
	
	private final Logger	logger	= Logger.getLogger(AESCrypto.class);
	
	private final String	cipherMode;
	private final String	cipherPaddingType;
	private final Cipher	cipher;
	
	// istanzia AESCrypto con modalità di cifratura/tipo di padding di default
	public AESCrypto() {
		
		this(	CipherModes.ECB,
				CipherPaddingTypes.PKCS5);
	}
	
	public AESCrypto(	String cipherMode,
						String cipherPaddingType) {
		
		this.cipherMode = cipherMode;
		this.cipherPaddingType = cipherPaddingType;
		
		// istanzia cifratore, specificando l'algoritmo da impiegare
		// (opzionalmente anche modalità e tipo di padding)
		try {
			
			this.cipher = Cipher.getInstance(this.getCipherAlgorithm());
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("errore.inizializzazione.cifratore",
																		this.getCipherAlgorithm()));
		}
	}
	
	@Override
	public String getAlgorithm() {
		
		return CipherAlgorithms.AES;
	}
	
	@Override
	public String getCipherMode() {
		
		return this.cipherMode;
	}
	
	@Override
	public String getCipherPaddingType() {
		
		return this.cipherPaddingType;
	}
	
	@Override
	public Cipher getCipher() {
		
		return this.cipher;
	}
	
	/**
	 * @param textToEncrypt
	 * @param secretKey
	 * @param initVector
	 *            opzionale - initialization vector necessario in caso di cifratura a blocchi (Cipher in modalità CBC)
	 * @param encoding
	 * @param hexEncoding
	 * @param explicitPadding
	 * @return
	 */
	public String encrypt(	String textToEncrypt,
							SecretKey secretKey,
							byte[] initVector,
							Charset encoding,
							boolean hexEncoding,
							boolean explicitPadding) {
		
		try {
			
			// inizializza il cifratore con la chiave di cifratura e l'initialization vector specificati
			if (this.getCipherMode().equals(CipherModes.CBC)) {
				
				this.getCipher().init(	Cipher.ENCRYPT_MODE,
										secretKey,
										new IvParameterSpec(initVector));
			}
			else {
				
				this.getCipher().init(	Cipher.ENCRYPT_MODE,
										secretKey);
			}
			
			if (encoding == null)
				encoding = EncodingUtil.DEFAULT_CHARSET;
			
			String paddedTextToEncrypt = null;
			byte[] textToEncryptPaddedBytes = null;
			
			// se specificato, manipola il testo in modo da garantire che risulti di una lunghezza multipla rispetto a quella dei blocchi di cifratura
			if (hexEncoding) {
				
				// conversione del testo in esadecimale
				paddedTextToEncrypt = EncodingUtil.bytesToHexString(textToEncrypt.getBytes(encoding));
			}
			else if (explicitPadding) {
				
				paddedTextToEncrypt = StringUtils.rightPad(	textToEncrypt,
															NumberUtil.calcolaProssimoMultiplo(	textToEncrypt.length(),
																								this.getCipherBlockSize()),
															EncodingUtil.PADDING_CHAR);
			}
			// nessun tipo di padding richiesto
			else {
				
				paddedTextToEncrypt = textToEncrypt;
			}
			
			textToEncryptPaddedBytes = paddedTextToEncrypt.getBytes(encoding);
			
			// esegui cifratura
			byte[] encryptedTextBytes = this.getCipher().doFinal(textToEncryptPaddedBytes);
			
			// restituisce il testo cifrato, codificato in esadecimale
			return EncodingUtil.bytesToHexString(encryptedTextBytes);
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("errore.operazione.cifratura"));
		}
	}
	
	/**
	 * @param textToDecrypt
	 * @param secretKey
	 * @param initVector
	 *            opzionale - initialization vector necessario in caso di cifratura a blocchi (Cipher in modalità CBC)
	 * @param encoding
	 * @param hexEncoding
	 * @return
	 */
	public String decrypt(	String textToDecrypt,
							SecretKey secretKey,
							byte[] initVector,
							Charset encoding,
							boolean hexEncoding) {
		
		try {
			
			// inizializza il decifratore con la chiave di decifratura e l'initialization vector specificati
			if (this.getCipherMode().equals(CipherModes.CBC)) {
				
				this.getCipher().init(	Cipher.DECRYPT_MODE,
										secretKey,
										new IvParameterSpec(initVector));
			}
			else {
				
				this.getCipher().init(	Cipher.DECRYPT_MODE,
										secretKey);
				
			}
			
			if (encoding == null)
				encoding = EncodingUtil.DEFAULT_CHARSET;
			
			// recupera la rappresentazione in byte della stringa esadecimale cifrata
			byte[] textToDecryptBytes = EncodingUtil.hexStringToBytes(textToDecrypt);
			
			// esegui decifratura
			byte[] decryptedTextBytes = this.getCipher().doFinal(textToDecryptBytes);
			
			// restituisce la stringa decifrata
			if (hexEncoding) {
				
				// in rappresentazione esadecimale
				return new String(	EncodingUtil.hexStringToBytes(new String(decryptedTextBytes)),
									encoding);
			}
			else {
				
				// nella codifica originaria
				return new String(	decryptedTextBytes,
									encoding);
			}
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("errore.operazione.decifratura"));
		}
	}
	
}