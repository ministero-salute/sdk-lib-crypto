package it.gov.salute.crypto.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import it.gov.salute.crypto.beans.CipherPropertiesEnum;
import it.gov.salute.crypto.constants.FileStandards;
import it.gov.salute.crypto.constants.PemObjectTypes;

/**
 * @author alessandro.imperio
 *
 */
public class CryptoUtil {
	
	@SuppressWarnings("unused")
	private static final Logger			logger					= Logger.getLogger(CryptoUtil.class);
	
	private static final SecureRandom	randomGenerator;
	
	// limite massimo teorico per la dimensione del numero seriale relativo ai certificati (2^159 - 1)
	// (in numero di bit)
	// RFC 5280
	// 4.1.2.2. Serial Number
	public static final int				CERT_SERIAL_NUMBER_BITS	= 159;
	
	private static final String			CERTIFICATE_PREFIX		= "-----BEGIN CERTIFICATE-----";
	private static final String			CERTIFICATE_SUFFIX		= "-----END CERTIFICATE-----";
	
	private static final String			PUBLIC_KEY_PREFIX		= "-----BEGIN PUBLIC KEY-----";
	private static final String			PUBLIC_KEY_SUFFIX		= "-----END PUBLIC KEY-----";
	
	private static final String			PRIVATE_KEY_PREFIX		= "-----BEGIN PRIVATE KEY-----";
	private static final String			PRIVATE_KEY_SUFFIX		= "-----END PRIVATE KEY-----";
	
	static {
		
		randomGenerator = new SecureRandom();
	}
	
	/**
	 * @param algorithm
	 * @param cipherMode
	 * @param paddingType
	 * @return
	 */
	public static String generateCipherTransformationString(String algorithm,
															String cipherMode,
															String paddingType) {
		
		return algorithm.concat((StringUtils.isNotEmpty(cipherMode) && StringUtils.isNotEmpty(paddingType)) ? "/".concat(cipherMode).concat("/").concat(paddingType) : "");
	}
	
	/**
	 * genera il valore per un campo "Subject" di un certificato, a partire dai vari possibili RDN (Relative Distinguished Names)
	 * 
	 * CN -> Your name (or the name of your CA)
	 * E -> e-mail address
	 * OU -> Organizational unit
	 * O -> Organization
	 * L -> Locality or city
	 * ST -> State or province
	 * C -> Country code (2 characters)
	 * 
	 * @param commonName
	 * @param organizationalUnit
	 * @param organization
	 * @param locality
	 * @param stateOrProvinceName
	 * @param countryCode
	 * @return
	 */
	public static X500Name generateX500Name(String commonName,
											String organizationalUnit,
											String organization,
											String locality,
											String stateOrProvinceName,
											String countryCode) {
		
		List<RDN> relativeDistinguishedNames = new ArrayList<RDN>();
		
		if (StringUtils.isNotBlank(commonName))
			relativeDistinguishedNames.add(new RDN(new AttributeTypeAndValue(	BCStyle.CN,
																				new DERUTF8String(commonName))));
		
		if (StringUtils.isNotBlank(organizationalUnit))
			relativeDistinguishedNames.add(new RDN(new AttributeTypeAndValue(	BCStyle.OU,
																				new DERUTF8String(organizationalUnit))));
		
		if (StringUtils.isNotBlank(organization))
			relativeDistinguishedNames.add(new RDN(new AttributeTypeAndValue(	BCStyle.O,
																				new DERUTF8String(organization))));
		
		if (StringUtils.isNotBlank(locality))
			relativeDistinguishedNames.add(new RDN(new AttributeTypeAndValue(	BCStyle.L,
																				new DERUTF8String(locality))));
		
		if (StringUtils.isNotBlank(stateOrProvinceName))
			relativeDistinguishedNames.add(new RDN(new AttributeTypeAndValue(	BCStyle.ST,
																				new DERUTF8String(stateOrProvinceName))));
		
		if (StringUtils.isNotBlank(countryCode))
			relativeDistinguishedNames.add(new RDN(new AttributeTypeAndValue(	BCStyle.C,
																				new DERUTF8String(countryCode))));
		
		return new X500Name(relativeDistinguishedNames.toArray(new RDN[relativeDistinguishedNames.size()]));
	}
	
	/**
	 * Restituisce una rappresentazione in stringa delle identit� dei firmatari specificati come parametro
	 * 
	 * @param signersInfo
	 * @return
	 */
	public static String getSignersNames(SignerInformationStore signersInfo) {
		
		StringBuilder signersBuilder = new StringBuilder();
		X500NameStyle x500NameStyle = BCStyle.INSTANCE;
		for (SignerInformation signerInformation : signersInfo.getSigners()) {
			
			if (signerInformation != null) {
				
				if (signersBuilder.length() > 0) {
					
					signersBuilder.append(" -> ");
				}
				signersBuilder.append("[");
				signersBuilder.append(x500NameStyle.toString(signerInformation.getSID().getIssuer()));
				signersBuilder.append("]");
			}
		}
		
		return signersBuilder.toString();
	}
	
	public static BigInteger generateRandomSerialNumber() {
		
		return new BigInteger(	CERT_SERIAL_NUMBER_BITS,
								randomGenerator);
	}
	
	/**
	 * @param size
	 *            deve essere pari alla dimensione (in byte) dei blocchi utilizzati dall'algoritmo di cifratura impiegato (NON della chiave)
	 * @return
	 */
	public static byte[] generateInitVector(int size) {
		
		byte[] initializationVector = new byte[size];
		randomGenerator.nextBytes(initializationVector);
		return initializationVector;
	}
	
	/**
	 * determina la lunghezza della chiave e la adatta ai tagli consentiti
	 * criterio: padding superiore fino alla dimensione direttamente successiva nell'insieme dei tagli consentiti..
	 * ..entro e non oltre la dimensione dell'ultimo taglio configurato
	 * 
	 * @param actualKeyLength
	 * @param allowedKeyLengths
	 * @return
	 */
	public static int calculatePaddedKeyLength(	int actualKeyLength,
												List<Integer> allowedKeyLengths) {
		
		Iterator<Integer> lengthsIterator = allowedKeyLengths.iterator();
		int lowerBound = 0;
		int upperBound;
		while (lengthsIterator.hasNext()) {
			
			upperBound = lengthsIterator.next();
			if (lowerBound < actualKeyLength &&
					actualKeyLength <= upperBound) {
				
				return upperBound;
			}
			lowerBound = upperBound;
		}
		
		// default: se non ha determinato una dimensione seleziona l'ultima tra quelle definite
		return allowedKeyLengths.get(allowedKeyLengths.size() - 1);
	}
	
	/**
	 * @param algorithm
	 * @param keyLength
	 *            (in bit)
	 * @param allowedKeyLengths
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey generateRandomKey(	String algorithm,
												int keyLength,
												List<Integer> allowedKeyLengths)
			throws NoSuchAlgorithmException {
		
		if (!allowedKeyLengths.contains(keyLength)) {
			
			throw new RuntimeException(LibProperties.getMessageProperty("chiave.cifratura.dimensione.non.consentita",
																		allowedKeyLengths.toString()));
		}
		KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
		keyGen.init(keyLength);
		return keyGen.generateKey();
	}
	
	/**
	 * @param keyString
	 * @param algorithm
	 * @param allowedKeyLengths
	 * @param encoding
	 * @return
	 */
	public static SecretKey generateKeyFromString(	String keyString,
													String algorithm,
													List<Integer> allowedKeyLengths,
													Charset encoding) {
		
		if (keyString == null)
			throw new RuntimeException(LibProperties.getMessageProperty("chiave.cifratura.non.valida"));
		
		if (encoding == null)
			encoding = EncodingUtil.DEFAULT_CHARSET;
		
		keyString = keyString.trim();
		
		int actualKeyLengthInBits = keyString.length() * 8; // in bit
		int paddedKeyLengthInBytes = CryptoUtil.calculatePaddedKeyLength(	actualKeyLengthInBits,
																			allowedKeyLengths)
				/ 8;
		
		// recupera la rappresentazione in byte della chiave (oppurtunamente tagliata)
		byte[] keyBytes = keyString.getBytes(encoding);
		byte[] paddedKeyBytes = new byte[paddedKeyLengthInBytes];
		System.arraycopy(	keyBytes,
							0,
							paddedKeyBytes,
							0,
							Math.min(	keyBytes.length,
										paddedKeyBytes.length));
		
		// genera l'oggetto che rappresenta la chiave necessario all'algoritmo di cifratura
		return new SecretKeySpec(	paddedKeyBytes,
									algorithm);
	}
	
	/**
	 * 
	 * @param keyPairAlgorithm
	 * @param keyLength
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateKeyPair(	String keyPairAlgorithm,
											int keyLength)
			throws NoSuchAlgorithmException {
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance(keyPairAlgorithm);
		
		generator.initialize(	keyLength,
								new SecureRandom());
		
		return generator.generateKeyPair();
	}
	
	/**
	 * @param keyStorePath
	 * @param keyStoreType
	 * @param keyStorePassword
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	public static KeyStore getKeyStore(	String keyStorePath,
										String keyStoreType,
										char[] keyStorePassword)
			throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		
		try (InputStream keystoreInputStream = new FileInputStream(new File(keyStorePath));) {
			
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			
			keyStore.load(	keystoreInputStream,
							keyStorePassword);
			
			return keyStore;
		}
	}
	
	/**
	 * Retrieve a key pair stored in a keystore
	 * (for "JCEKS" type, it's generated with: keytool -genkeypair -alias mykey -storepass <keystorePassword> -keypass <keyPassword> -keyalg <keyAlgorithm> -keystore <keystorePath>)
	 * 
	 * @param keyStore
	 * @param alias
	 * @param keyPairPassword
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws KeyStoreException
	 */
	public static KeyPair getKeyPairFromKeyStore(	KeyStore keyStore,
													String alias,
													char[] keyPairPassword)
			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		
		KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(keyPairPassword);
		
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
																								passwordProtection);
		
		Certificate certificate = keyStore.getCertificate(alias);
		PublicKey publicKey = certificate.getPublicKey();
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		
		return new KeyPair(	publicKey,
							privateKey);
	}
	
	/**
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws KeyStoreException
	 * @throws CertificateEncodingException
	 */
	public static JcaCertStore createJcaCertStoreFromKeyStore(	KeyStore keyStore,
																String alias)
			throws KeyStoreException, CertificateEncodingException {
		
		Certificate[] certificateChain = (Certificate[]) keyStore.getCertificateChain(alias);
		
		return createJcaCertStore(certificateChain);
	}
	
	/**
	 * @param certificates
	 * @return
	 */
	private static List<Certificate> getCertificatesList(Certificate[] certificates) {
		
		List<Certificate> certificateList = new ArrayList<Certificate>();
		
		for (int i = 0, length = certificates == null ? 0 : certificates.length; i < length; i++) {
			
			certificateList.add(certificates[i]);
		}
		
		return certificateList;
	}
	
	/**
	 * @param certificates
	 * @return
	 * @throws CertificateEncodingException
	 */
	public static JcaCertStore createJcaCertStore(Certificate... certificates) throws CertificateEncodingException {
		
		return new JcaCertStore(getCertificatesList(certificates));
	}
	
	/**
	 * @param securityProvider
	 * @param certificates
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static CertStore createCertStore(Provider securityProvider,
											Certificate... certificates)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		
		return CertStore.getInstance(	"Collection",
										new CollectionCertStoreParameters(getCertificatesList(certificates)),
										securityProvider);
	}
	
	/**
	 * @param keyStore
	 * @param alias
	 * @param securityProvider
	 * @return
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static X509Certificate getX509CertificateFromKeystore(	KeyStore keyStore,
																	String alias,
																	Provider securityProvider)
			throws KeyStoreException, IOException, CertificateException {
		
		Certificate certificate = keyStore.getCertificate(alias);
		
		X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());
		
		return new JcaX509CertificateConverter().setProvider(securityProvider)
				.getCertificate(certificateHolder);
	}
	
	/**
	 * @param keyStore
	 * @param alias
	 * @param securityProvider
	 * @return
	 * @throws CertificateException
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public static PublicKey getPublicKeyFromKeystore(	KeyStore keyStore,
														String alias,
														Provider securityProvider)
			throws CertificateException, KeyStoreException, IOException {
		
		X509Certificate certificate = getX509CertificateFromKeystore(	keyStore,
																		alias,
																		securityProvider);
		return certificate.getPublicKey();
	}
	
	/**
	 * @param keyStore
	 * @param alias
	 * @param keyPassword
	 * @return
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 */
	public static PrivateKey getPrivateKeyFromKeystore(	KeyStore keyStore,
														String alias,
														char[] keyPassword)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		
		Key key = keyStore.getKey(	alias,
									keyPassword);
		if (key instanceof PrivateKey) {
			
			return (PrivateKey) key;
		}
		else {
			
			throw new UnrecoverableKeyException();
		}
	}
	
	/**
	 * secondo standard X509
	 * 
	 * @param certificateString
	 * @param securityProvider
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static X509Certificate getX509CertificateFromString(	String certificateString,
																Provider securityProvider)
			throws CertificateException, IOException {
		
		// remove private key prefix and suffix
		certificateString = certificateString.replaceAll(	CERTIFICATE_PREFIX,
															"");
		certificateString = certificateString.replaceAll(	CERTIFICATE_SUFFIX,
															"");
		
		// consider only the base64 chars
		certificateString = EncodingUtil.filterBase64String(certificateString);
		
		// decode base64 encoded string
		byte[] certificateDecodedBytes = Base64.decodeBase64(certificateString);
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance(	FileStandards.X509_CERTIFICATE,
																				securityProvider);
		
		try (ByteArrayInputStream certificateByteArrayInputStream = new ByteArrayInputStream(certificateDecodedBytes);) {
			
			return (X509Certificate) certificateFactory.generateCertificate(certificateByteArrayInputStream);
		}
	}
	
	/**
	 * secondo standard X509
	 *
	 * @param publicKeyBytes
	 * @param keyPairAlgorithm
	 * @param securityProvider
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey getPublicKeyFromBytes(	byte[] publicKeyBytes,
													String keyPairAlgorithm,
													Provider securityProvider)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		
		KeyFactory keyFactory = KeyFactory.getInstance(	keyPairAlgorithm,
														securityProvider);
		
		return keyFactory.generatePublic(keySpec);
	}
	
	/**
	 * @param publicKeyString
	 * @param keyPairAlgorithm
	 * @param pemFormat
	 * @param securityProvider
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey getPublicKeyFromString(	String publicKeyString,
													String keyPairAlgorithm,
													boolean pemFormat,
													Provider securityProvider)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] publicKeyBytes = null;
		
		if (pemFormat) {
			
			// remove public key prefix and suffix
			publicKeyString = publicKeyString.replaceAll(	PUBLIC_KEY_PREFIX,
															"");
			publicKeyString = publicKeyString.replaceAll(	PUBLIC_KEY_SUFFIX,
															"");
			
			// consider only the base64 chars
			publicKeyString = EncodingUtil.filterBase64String(publicKeyString);
			
			// decode base64 encoded string
			publicKeyBytes = Base64.decodeBase64(publicKeyString);
		}
		else {
			
			publicKeyBytes = publicKeyString.getBytes();
		}
		
		return getPublicKeyFromBytes(	publicKeyBytes,
										keyPairAlgorithm,
										securityProvider);
	}
	
	/**
	 * secondo standard PKCS8
	 * 
	 * @param privateKeyBytes
	 * @param keyPairAlgorithm
	 * @param securityProvider
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey getPrivateKeyFromBytes(byte[] privateKeyBytes,
													String keyPairAlgorithm,
													Provider securityProvider)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		
		KeyFactory keyFactory = KeyFactory.getInstance(	keyPairAlgorithm,
														securityProvider);
		
		return keyFactory.generatePrivate(keySpec);
	}
	
	/**
	 * @param privateKeyString
	 * @param keyPairAlgorithm
	 * @param pemFormat
	 * @param securityProvider
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey getPrivateKeyFromString(	String privateKeyString,
														String keyPairAlgorithm,
														boolean pemFormat,
														Provider securityProvider)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] privateKeyBytes = null;
		
		if (pemFormat) {
			
			// remove private key prefix and suffix
			privateKeyString = privateKeyString.replaceAll(	PRIVATE_KEY_PREFIX,
															"");
			privateKeyString = privateKeyString.replaceAll(	PRIVATE_KEY_SUFFIX,
															"");
			
			// consider only the base64 chars
			privateKeyString = EncodingUtil.filterBase64String(privateKeyString);
			
			// decode base64 encoded string
			privateKeyBytes = Base64.decodeBase64(privateKeyString);
		}
		else {
			
			privateKeyBytes = privateKeyString.getBytes();
		}
		
		return getPrivateKeyFromBytes(	privateKeyBytes,
										keyPairAlgorithm,
										securityProvider);
	}
	
	/**
	 * secondo standard X509
	 * TODO provare a sostituire PEMParser con PEMReader
	 * 
	 * @param certificateInputStream
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static X509Certificate getX509CertificateFromStream(InputStream certificateInputStream)
			throws IOException, CertificateException {
		
		try (PEMParser pemParser = new PEMParser(new InputStreamReader(certificateInputStream));) {
			
			Object object = pemParser.readObject();
			
			if (object instanceof X509CertificateHolder) {
				
				JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
				return converter.getCertificate((X509CertificateHolder) object);
			}
			else {
				
				throw new IllegalArgumentException("data read from stream don't represent a valid X509Certificate");
			}
		}
	}
	
	/**
	 * TODO provare a sostituire PEMParser con PEMReader
	 * 
	 * @param publicKeyInputStream
	 * @return
	 * @throws IOException
	 */
	public static PublicKey getPublicKeyFromStream(InputStream publicKeyInputStream)
			throws IOException {
		
		try (PEMParser pemParser = new PEMParser(new InputStreamReader(publicKeyInputStream));) {
			
			Object object = pemParser.readObject();
			
			if (object instanceof SubjectPublicKeyInfo) {
				
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
				return converter.getPublicKey((SubjectPublicKeyInfo) object);
			}
			else {
				
				throw new IllegalArgumentException("data read from stream don't represent a valid PublicKey");
			}
		}
	}
	
	/**
	 * 
	 * TODO provare a sostituire PEMParser con PEMReader
	 * 
	 * @param privateKeyInputStream
	 * @return
	 * @throws IOException
	 */
	public static PrivateKey getPrivateKeyFromStream(InputStream privateKeyInputStream) throws IOException {
		
		try (PEMParser pemParser = new PEMParser(new InputStreamReader(privateKeyInputStream));) {
			
			Object object = pemParser.readObject();
			
			if (object instanceof PrivateKeyInfo) {
				
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
				return converter.getPrivateKey((PrivateKeyInfo) object);
			}
			else {
				
				throw new IllegalArgumentException("data read from stream don't represent a valid PrivateKey");
			}
		}
	}
	
	/**
	 * 
	 * scrive il contenuto del PemObject specificato sull'OutputStream fornito
	 * 
	 * @param privateKeyInputStream
	 * @return
	 * @throws IOException
	 */
	public static void writePemObjectOnStream(	PemObject pemObject,
												OutputStream outputStream)
			throws IOException {
		
		try (OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream);
				PemWriter pemWriter = new PemWriter(outputStreamWriter);) {
			
			pemWriter.writeObject(pemObject);
			pemWriter.flush();
		}
	}
	
	/**
	 * 
	 * @param keyPair
	 * @param subjectX500Name
	 * @param securityProvider
	 * @param signatureAlgorithm
	 * @param startDate,
	 * @param expiryDate
	 * @param serialNumber
	 * @return
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws CertificateException
	 */
	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair,
																X500Name subjectX500Name,
																Provider securityProvider,
																String signatureAlgorithm,
																Date issueDate,
																Date expiryDate,
																BigInteger serialNumber)
			throws OperatorCreationException, CertIOException, CertificateException {
		
		// Signer --------------------------
		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
		// ---------------------------------
		
		// Certificate Builder -------------
		JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(	subjectX500Name,
																							serialNumber,
																							issueDate,
																							expiryDate,
																							subjectX500Name,
																							keyPair.getPublic());
		// ---------------------------------
		
		// Extensions ----------------------
		
		// Basic Constraints (subject considerato come CA)
		certificateBuilder.addExtension(Extension.basicConstraints, // ASN1 OID -> "2.5.29.19"
										true,
										new BasicConstraints(true));
		// ---------------------------------
		
		return new JcaX509CertificateConverter().setProvider(securityProvider).getCertificate(certificateBuilder.build(contentSigner));
	}
	
	/**
	 * genera una coppia di chiavi RSA random ed un certificato self-signed (associato alla pubblica della coppia, e firmato con la privata)
	 * 
	 * @param subjectX500Name
	 * @param securityProvider
	 * @param signatureAlgorithm
	 * @param issueDate
	 * @param expiryDate
	 * @param serialNumber
	 * @param publicKeyOutputStream
	 * @param privateKeyOutputStream
	 * @param certificateOutputStream
	 * @throws Exception
	 */
	public static void createRSAKeyPairAndSelfSignedCertificate(int keyLength,
																X500Name subjectX500Name,
																Provider securityProvider,
																String signatureAlgorithm,
																Date issueDate,
																Date expiryDate,
																BigInteger serialNumber,
																OutputStream publicKeyOutputStream,
																OutputStream privateKeyOutputStream,
																OutputStream certificateOutputStream)
			throws Exception {
		
		// generazione coppia di chiavi random
		KeyPair keyPair = CryptoUtil.generateKeyPair(	CipherPropertiesEnum.RSA.getAlgorithm(),
														keyLength);
		
		// scrittura chiave pubblica
		PemObject publicKeyPemObject = new PemObject(	PemObjectTypes.PUBLIC_KEY,
														keyPair.getPublic().getEncoded());
		writePemObjectOnStream(	publicKeyPemObject,
								publicKeyOutputStream);
		
		// scrittura chiave privata
		PemObject privateKeyPemObject = new PemObject(	PemObjectTypes.PRIVATE_KEY,
														keyPair.getPrivate().getEncoded());
		writePemObjectOnStream(	privateKeyPemObject,
								privateKeyOutputStream);
		
		X509Certificate certificate = CryptoUtil.generateSelfSignedCertificate(	keyPair,
																				subjectX500Name,
																				securityProvider,
																				signatureAlgorithm,
																				issueDate,
																				expiryDate,
																				serialNumber);
		
		// scrittura certificato
		PemObject certificatePemObject = new PemObject(	PemObjectTypes.CERTIFICATE,
														certificate.getEncoded());
		writePemObjectOnStream(	certificatePemObject,
								certificateOutputStream);
	}
	
}
