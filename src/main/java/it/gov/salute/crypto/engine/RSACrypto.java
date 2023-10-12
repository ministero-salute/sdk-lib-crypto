package it.gov.salute.crypto.engine;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import it.gov.salute.crypto.constants.CipherAlgorithms;
import it.gov.salute.crypto.constants.CipherModes;
import it.gov.salute.crypto.constants.CipherPaddingTypes;
import it.gov.salute.crypto.constants.SignatureAlgorithms;
import it.gov.salute.crypto.utils.EncodingUtil;
import it.gov.salute.crypto.utils.LibProperties;

/**
 * @author alessandro.imperio
 *
 */
public class RSACrypto extends CipherCrypto {
	
	private static final Logger	logger	= Logger.getLogger(RSACrypto.class);
	
	private final String		cipherMode;
	private final String		cipherPaddingType;
	private final String		signatureAlgorithm;
	private final Cipher		cipher;
	private final Signature		signature;
	
	// istanzia RSACrypto con algoritmo di firma di default
	public RSACrypto() {
		
		this(	SignatureAlgorithms.SHA1_RSA,
				CipherModes.ECB,
				CipherPaddingTypes.NO_PADDING);
	}
	
	public RSACrypto(	String signatureAlgorithm,
						String cipherMode,
						String cipherPaddingType) {
		
		this.cipherMode = cipherMode;
		this.cipherPaddingType = cipherPaddingType;
		this.signatureAlgorithm = signatureAlgorithm;
		
		// istanzia cifratore e firmatore, specificando gli algoritmi da impiegare
		try {
			
			this.cipher = Cipher.getInstance(this.getCipherAlgorithm());
			this.signature = Signature.getInstance(this.getSignatureAlgorithm());
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("errore.inizializzazione.cifratore",
																		this.getCipherAlgorithm().concat(" - ").concat(this.getSignatureAlgorithm())));
		}
	}
	
	@Override
	public String getAlgorithm() {
		
		return CipherAlgorithms.RSA;
	}
	
	@Override
	public String getCipherMode() {
		
		return this.cipherMode;
	}
	
	@Override
	public String getCipherPaddingType() {
		
		return this.cipherPaddingType;
	}
	
	public String getSignatureAlgorithm() {
		
		return this.signatureAlgorithm;
	}
	
	@Override
	public Cipher getCipher() {
		
		return this.cipher;
	}
	
	public Signature getSignature() {
		
		return this.signature;
	}
	
	/**
	 * @param plainText
	 * @param encoding
	 * @param publicKey
	 * @return
	 */
	public String encrypt(	String plainText,
							Charset encoding,
							PublicKey publicKey) {
		
		try {
			
			// inizializza il cifratore con la chiave di cifratura (pubblica)
			getCipher().init(	Cipher.ENCRYPT_MODE,
								publicKey);
			
			if (encoding == null)
				encoding = EncodingUtil.DEFAULT_CHARSET;
			
			byte[] encryptedTextBytes = this.getCipher().doFinal(plainText.getBytes(encoding));
			
			return Base64.encodeBase64String(encryptedTextBytes);
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("errore.operazione.cifratura"));
		}
	}
	
	/**
	 * @param encryptedText
	 * @param encoding
	 * @param privateKey
	 * @return
	 */
	public String decrypt(	String encryptedText,
							Charset encoding,
							PrivateKey privateKey) {
		
		try {
			
			// inizializza il decifratore con la chiave di decifratura (privata)
			getCipher().init(	Cipher.DECRYPT_MODE,
								privateKey);
			
			byte[] encryptedTextBytes = Base64.decodeBase64(encryptedText);
			
			if (encoding == null)
				encoding = EncodingUtil.DEFAULT_CHARSET;
			
			return new String(	this.getCipher().doFinal(encryptedTextBytes),
								encoding);
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("errore.operazione.decifratura"));
		}
	}
	
	/**
	 * @param identity
	 * @param encoding
	 * @param privateKey
	 * @return
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public String sign(	String identity,
						Charset encoding,
						PrivateKey privateKey)
			throws InvalidKeyException, SignatureException {
		
		this.getSignature().initSign(privateKey);
		
		if (encoding == null)
			encoding = EncodingUtil.DEFAULT_CHARSET;
		
		this.getSignature().update(identity.getBytes(encoding));
		
		byte[] signatureBytes = this.getSignature().sign();
		
		return Base64.encodeBase64String(signatureBytes);
	}
	
	/**
	 * @param identity
	 * @param encoding
	 * @param signatureString
	 * @param publicKey
	 * @return
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public boolean verify(	String identity,
							Charset encoding,
							String signatureString,
							PublicKey publicKey)
			throws InvalidKeyException, SignatureException {
		
		this.getSignature().initVerify(publicKey);
		
		if (encoding == null)
			encoding = EncodingUtil.DEFAULT_CHARSET;
		
		this.getSignature().update(identity.getBytes(encoding));
		
		byte[] signatureEncodedBytes = Base64.decodeBase64(signatureString);
		
		return this.getSignature().verify(signatureEncodedBytes);
	}
	
}
