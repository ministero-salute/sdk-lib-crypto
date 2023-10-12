package it.gov.salute.crypto.engine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import it.gov.salute.crypto.beans.CipherPropertiesEnum;
import it.gov.salute.crypto.utils.FileUtil;

/**
 * original copy taken from org.bouncycastle.openpgp.examples
 *
 * @author seamans
 * 
 * @modifiedby alessandro.imperio
 *
 */
public class PGPCrypto extends BCCrypto {
	
	@SuppressWarnings("unused")
	private static final Logger						logger	= Logger.getLogger(PGPCrypto.class);
	
	private static final BcKeyFingerprintCalculator	keyFingerprintCalculator;
	
	private static final int						BUFFER_SIZE;
	private static final int						KEY_FLAGS;
	private static final int[]						MASTER_KEY_CERTIFICATION_TYPES;
	
	// Asymmetric-key algorithm for the public/private key pair
	private static final String						KEY_PAIR_ALGORITHM;
	private static final int						KEY_PAIR_ALGORITHM_KEY_LENGTH;
	
	// Symmetric-key algorithm utilized to cipher the secret key
	private static final int						KEY_ENCRYPTION_ALGORITHM;
	
	// Hash algorithm utilized to generate the message digest and to code the secret key
	private static final int						HASH_ALGORITHM;
	
	// Compression algorithm utilized to compress the data before encryption (and to decompress data after decryption)
	private static final int						DATA_COMPRESSION_ALGORITHM;
	
	// Symmetric-key algorithm utilized to cipher the data
	// available algorithms -> AES, BLOWFISH, CAMELLIA, CAST5, DES, IDEA, SAFER, TRIPLE DES, TWOFISH
	private static final int						DATA_ENCRYPTION_ALGORITHM;
	
	private static final String						PRIVATE_KEY_EXPORT;
	private static final String						PUBLIC_KEY_EXPORT;
	
	static {
		
		keyFingerprintCalculator = new BcKeyFingerprintCalculator();
		
		// 2^16 -> 64KB
		BUFFER_SIZE = 1 << 16;
		KEY_FLAGS = 27;
		
		MASTER_KEY_CERTIFICATION_TYPES = new int[] {
				PGPSignature.POSITIVE_CERTIFICATION, PGPSignature.CASUAL_CERTIFICATION, PGPSignature.NO_CERTIFICATION, PGPSignature.DEFAULT_CERTIFICATION
		};
		
		KEY_PAIR_ALGORITHM = CipherPropertiesEnum.RSA.getAlgorithm();
		KEY_PAIR_ALGORITHM_KEY_LENGTH = CipherPropertiesEnum.RSA.getDefaultKeyLength();
		
		KEY_ENCRYPTION_ALGORITHM = PGPEncryptedData.CAST5;
		
		HASH_ALGORITHM = HashAlgorithmTags.SHA1;
		
		DATA_COMPRESSION_ALGORITHM = PGPCompressedData.ZIP;
		DATA_ENCRYPTION_ALGORITHM = PGPEncryptedData.TRIPLE_DES;
		
		PRIVATE_KEY_EXPORT = "private_key.pgp";
		PUBLIC_KEY_EXPORT = "public_key.pgp";
	}
	
	/**
	 * @param privateKeyOutputStream
	 * @param publicKeyOutputStream
	 * @param keyPair
	 * @param identity
	 * @param passphrase
	 * @param asciiArmor
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 * @throws PGPException
	 */
	public static void exportKeyPair(	OutputStream privateKeyOutputStream,
										OutputStream publicKeyOutputStream,
										KeyPair keyPair,
										String identity,
										char[] passphrase,
										boolean asciiArmor)
			throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
		
		try {
			
			PGPPublicKey pgpPublicKey = (new JcaPGPKeyConverter().getPGPPublicKey(	PGPPublicKey.RSA_GENERAL,
																					keyPair.getPublic(),
																					new Date()));
			RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
			RSASecretBCPGKey rsaSecretKey = new RSASecretBCPGKey(	privateKey.getPrivateExponent(),
																	privateKey.getPrimeP(),
																	privateKey.getPrimeQ());
			PGPPrivateKey pgpPrivateKey = new PGPPrivateKey(pgpPublicKey.getKeyID(),
															pgpPublicKey.getPublicKeyPacket(),
															rsaSecretKey);
			
			PGPKeyPair pgpKeyPair = new PGPKeyPair(	pgpPublicKey,
													pgpPrivateKey);
			
			PGPDigestCalculator secretKeyHashCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HASH_ALGORITHM);
			
			JcaPGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(	pgpKeyPair.getPublicKey().getAlgorithm(),
																								HASH_ALGORITHM);
			
			PBESecretKeyEncryptor secretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(	KEY_ENCRYPTION_ALGORITHM,
																							secretKeyHashCalculator).setProvider(getSecurityProvider()).build(passphrase);
			
			PGPSecretKey pgpSecretKey = new PGPSecretKey(	PGPSignature.DEFAULT_CERTIFICATION,
															pgpKeyPair,
															identity,
															secretKeyHashCalculator,
															null,
															null,
															contentSignerBuilder,
															secretKeyEncryptor);
			
			// write the coded private key on the provided stream
			if (asciiArmor) {
				
				privateKeyOutputStream = new ArmoredOutputStream(privateKeyOutputStream);
			}
			pgpSecretKey.encode(privateKeyOutputStream);
			
			// write the coded public key on the provided stream
			// PGPPublicKey key = pgpSecretKey.getPublicKey();
			if (asciiArmor) {
				
				publicKeyOutputStream = new ArmoredOutputStream(publicKeyOutputStream);
			}
			pgpPublicKey.encode(publicKeyOutputStream);
		}
		finally {
			
			if (privateKeyOutputStream != null)
				privateKeyOutputStream.close();
			
			if (publicKeyOutputStream != null)
				publicKeyOutputStream.close();
		}
	}
	
	/**
	 * @param identity
	 * @param passphrase
	 * @param exportKeyPair
	 * @param exportedKeyPairFolder
	 * @param asciiArmor
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 * @throws IOException
	 * @throws PGPException
	 */
	public static KeyPair generateKeyPair(	String identity,
											char[] passphrase,
											boolean exportKeyPair,
											String exportedKeyPairFolder,
											boolean asciiArmor)
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(	KEY_PAIR_ALGORITHM,
																			getSecurityProvider());
		keyPairGenerator.initialize(KEY_PAIR_ALGORITHM_KEY_LENGTH);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		if (exportKeyPair) {
			
			FileOutputStream privateKeyOutputStream = new FileOutputStream(exportedKeyPairFolder.concat(PRIVATE_KEY_EXPORT));
			FileOutputStream publicKeyOutputStream = new FileOutputStream(exportedKeyPairFolder.concat(PUBLIC_KEY_EXPORT));
			exportKeyPair(	privateKeyOutputStream,
							publicKeyOutputStream,
							keyPair,
							identity,
							passphrase,
							asciiArmor);
		}
		
		return keyPair;
	}
	
	/**
	 * @param publicKeyInputStream
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKey(InputStream publicKeyInputStream)
			throws IOException, PGPException {
		
		PGPPublicKeyRingCollection publicKeyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyInputStream),
																							keyFingerprintCalculator);
		
		Iterator<PGPPublicKeyRing> publicKeyRingsIterator = publicKeyRingCollection.getKeyRings();
		PGPPublicKeyRing pgpPublicKeyRing = null;
		Iterator<PGPPublicKey> publicKeysIterator = null;
		PGPPublicKey pgpPublicKey = null;
		PGPPublicKey pgpPublicKeyTemp = null;
		
		while (pgpPublicKey == null && publicKeyRingsIterator.hasNext()) {
			
			// TODO - in alternativa ricercare direttamente la chiave pubblica per keyID
			pgpPublicKeyRing = publicKeyRingsIterator.next();
			publicKeysIterator = pgpPublicKeyRing.getPublicKeys();
			
			while (pgpPublicKey == null && publicKeysIterator.hasNext()) {
				
				pgpPublicKeyTemp = publicKeysIterator.next();
				if (pgpPublicKeyTemp.isEncryptionKey()) {
					
					pgpPublicKey = pgpPublicKeyTemp;
				}
			}
		}
		
		if (pgpPublicKey == null) {
			
			throw new IllegalArgumentException("Can't find public key in the key ring.");
		}
		if (!isForEncryption(pgpPublicKey)) {
			
			throw new IllegalArgumentException("KeyID " + pgpPublicKey.getKeyID() + " not flagged for encryption.");
		}
		
		return pgpPublicKey;
	}
	
	/**
	 * From LockBox Lobs PGP Encryption tools.
	 * http://www.lockboxlabs.org/content/downloads
	 *
	 * @param pgpPublicKey
	 * @return
	 */
	@SuppressWarnings("deprecation")
	private static boolean isForEncryption(PGPPublicKey pgpPublicKey) {
		
		if (pgpPublicKey.getAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN
				|| pgpPublicKey.getAlgorithm() == PublicKeyAlgorithmTags.DSA
				|| pgpPublicKey.getAlgorithm() == PublicKeyAlgorithmTags.EC
				|| pgpPublicKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDSA) {
			return false;
		}
		
		return hasKeyFlags(	pgpPublicKey,
							KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
	}
	
	/**
	 * @param secretKeyInputStream
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	@SuppressWarnings("deprecation")
	public static PGPSecretKey readSecretKey(InputStream secretKeyInputStream)
			throws IOException, PGPException {
		
		PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(	PGPUtil.getDecoderStream(secretKeyInputStream),
																								keyFingerprintCalculator);
		
		Iterator<PGPSecretKeyRing> secretKeyRingsIterator = pgpSecretKeyRingCollection.getKeyRings();
		PGPSecretKeyRing pgpSecretKeyRing = null;
		Iterator<PGPSecretKey> secretKeysIterator = null;
		PGPSecretKey pgpSecretKey = null;
		PGPSecretKey pgpSecretKeyTemp = null;
		
		while (pgpSecretKey == null && secretKeyRingsIterator.hasNext()) {
			
			// TODO - in alternativa ricercare direttamente la chiave privata per keyID
			pgpSecretKeyRing = secretKeyRingsIterator.next();
			secretKeysIterator = pgpSecretKeyRing.getSecretKeys();
			
			while (pgpSecretKey == null && secretKeysIterator.hasNext()) {
				
				pgpSecretKeyTemp = secretKeysIterator.next();
				if (pgpSecretKeyTemp.isSigningKey()) {
					
					pgpSecretKey = pgpSecretKeyTemp;
				}
			}
		}
		
		if (pgpSecretKey == null) {
			
			throw new IllegalArgumentException("Can't find private key in the key ring.");
		}
		if (!pgpSecretKey.isSigningKey()) {
			
			throw new IllegalArgumentException("Private key does not allow signing.");
		}
		if (pgpSecretKey.getPublicKey().isRevoked()) {
			
			throw new IllegalArgumentException("Private key has been revoked.");
		}
		if (!hasKeyFlags(	pgpSecretKey.getPublicKey(),
							KeyFlags.SIGN_DATA)) {
			
			throw new IllegalArgumentException("Key cannot be used for signing.");
		}
		
		return pgpSecretKey;
	}
	
	/**
	 * From LockBox Lobs PGP Encryption tools.
	 * http://www.lockboxlabs.org/content/downloads
	 *
	 * @param pgpPublicKey
	 * @param keyUsage
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private static boolean hasKeyFlags(	PGPPublicKey pgpPublicKey,
										int keyUsage) {
		
		Iterator<PGPSignature> signatureIterator = null;
		PGPSignature pgpSignature = null;
		
		if (pgpPublicKey.isMasterKey()) {
			
			for (int i = 0; i != PGPCrypto.MASTER_KEY_CERTIFICATION_TYPES.length; i++) {
				
				for (signatureIterator = pgpPublicKey.getSignaturesOfType(PGPCrypto.MASTER_KEY_CERTIFICATION_TYPES[i]); signatureIterator.hasNext();) {
					
					pgpSignature = signatureIterator.next();
					if (!isMatchingUsage(	pgpSignature,
											keyUsage)) {
						return false;
					}
				}
			}
		}
		else {
			
			for (signatureIterator = pgpPublicKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING); signatureIterator.hasNext();) {
				
				pgpSignature = signatureIterator.next();
				if (!isMatchingUsage(	pgpSignature,
										keyUsage)) {
					return false;
				}
			}
		}
		
		return true;
	}
	
	/**
	 * From LockBox Lobs PGP Encryption tools.
	 * http://www.lockboxlabs.org/content/downloads
	 * 
	 * @param pgpSignature
	 * @param keyUsage
	 * @return
	 */
	private static boolean isMatchingUsage(	PGPSignature pgpSignature,
											int keyUsage) {
		
		if (pgpSignature.hasSubpackets()) {
			
			PGPSignatureSubpacketVector signatureSubpacketVector = pgpSignature.getHashedSubPackets();
			
			if (signatureSubpacketVector.hasSubpacket(PGPCrypto.KEY_FLAGS)) {
				
				if ((signatureSubpacketVector.getKeyFlags() & keyUsage) == 0) {
					
					return false;
				}
			}
		}
		
		return true;
	}
	
	/**
	 * Load a secret key ring collection from keyIn and find the private key corresponding to
	 * keyID if it exists.
	 *
	 * @param privateKeyInputStream
	 *            input stream representing a key ring collection.
	 * @param privateKeyID
	 *            keyID we want.
	 * @param passphrase
	 *            passphrase to decrypt secret key with.
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	public static PGPPrivateKey findPrivateKey(	InputStream privateKeyInputStream,
												long privateKeyID,
												char[] passphrase)
			throws IOException, PGPException, NoSuchProviderException {
		
		PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(	PGPUtil.getDecoderStream(privateKeyInputStream),
																								keyFingerprintCalculator);
		return findPrivateKey(	pgpSecretKeyRingCollection.getSecretKey(privateKeyID),
								passphrase);
	}
	
	/**
	 * Load a secret key and find the private key in it
	 * 
	 * @param pgpSecretKey
	 *            The secret key
	 * @param passphrase
	 *            passphrase to decrypt secret key with
	 * @return
	 * @throws PGPException
	 */
	private static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecretKey,
												char[] passphrase)
			throws PGPException {
		
		if (pgpSecretKey == null)
			return null;
		
		PBESecretKeyDecryptor pbeSecretKeyDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passphrase);
		return pgpSecretKey.extractPrivateKey(pbeSecretKeyDecryptor);
	}
	
	/**
	 * Encrypt the data read from the file specified, using as key the data read from publicKeyringInputStream and writing the result on the finalOutputStream
	 * 
	 * TODO - parametrizzare/sdoppiare metodo per permettere la lettura dei dati originari direttamente da uno stream anziché da file
	 * 
	 * @param originaryDataPath
	 * @param finalOutputStream
	 * @param publicKeyringInputStream
	 * @param compressData
	 * @param includeIntegrityPacket
	 * @param asciiArmor
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws PGPException
	 */
	public static void encryptData(	String originaryDataPath,
									OutputStream finalOutputStream,
									InputStream publicKeyringInputStream,
									boolean compressData,
									boolean includeIntegrityPacket,
									boolean asciiArmor)
			throws IOException, NoSuchProviderException, PGPException {
		
		ByteArrayOutputStream byteArrayOutputStream = null;
		PGPCompressedDataGenerator compressedDataGenerator = null;
		PGPEncryptedDataGenerator encryptedDataGenerator = null;
		
		try {
			
			int compressionAlgorithm;
			if (compressData) {
				
				compressionAlgorithm = DATA_COMPRESSION_ALGORITHM;
			}
			else {
				
				compressionAlgorithm = PGPCompressedData.UNCOMPRESSED;
			}
			
			byteArrayOutputStream = new ByteArrayOutputStream();
			compressedDataGenerator = new PGPCompressedDataGenerator(compressionAlgorithm);
			OutputStream originaryDataOutputStream = compressedDataGenerator.open(	byteArrayOutputStream,
																					new byte[PGPCrypto.BUFFER_SIZE]);
			PGPUtil.writeFileToLiteralData(	originaryDataOutputStream,
											PGPLiteralData.BINARY,
											new File(originaryDataPath));
		}
		finally {
			
			if (compressedDataGenerator != null)
				compressedDataGenerator.close();
		}
		
		try {
			
			byte[] compressedDataBytes = byteArrayOutputStream.toByteArray();
			
			BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(DATA_ENCRYPTION_ALGORITHM);
			dataEncryptorBuilder.setWithIntegrityPacket(includeIntegrityPacket);
			dataEncryptorBuilder.setSecureRandom(new SecureRandom());
			
			PGPPublicKey pgpPublicKey = PGPCrypto.readPublicKey(publicKeyringInputStream);
			
			encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
			encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pgpPublicKey));
			
			if (asciiArmor) {
				
				finalOutputStream = new ArmoredOutputStream(finalOutputStream);
			}
			
			OutputStream encryptedDataOutputStream = encryptedDataGenerator.open(	finalOutputStream,
																					compressedDataBytes.length);
			
			encryptedDataOutputStream.write(compressedDataBytes);
		}
		finally {
			
			if (byteArrayOutputStream != null)
				byteArrayOutputStream.close();
			
			if (encryptedDataGenerator != null)
				encryptedDataGenerator.close();
			
			if (finalOutputStream != null)
				finalOutputStream.close();
		}
	}
	
	/**
	 * Decrypt the data read from encryptedDataInputStream, using as private key the data read from privateKeyringInputStream and writing the result on the finalOutputStream
	 * 
	 * @param encryptedDataInputStream
	 * @param finalOutputStream
	 * @param privateKeyringInputStream
	 * @param passphrase
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public static void decryptData(	InputStream encryptedDataInputStream,
									OutputStream finalOutputStream,
									InputStream privateKeyringInputStream,
									char[] passphrase)
			throws IOException, NoSuchProviderException, PGPException {
		
		encryptedDataInputStream = PGPUtil.getDecoderStream(encryptedDataInputStream);
		
		PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(	encryptedDataInputStream,
																	keyFingerprintCalculator);
		PGPEncryptedDataList pgpEncryptedDataList = null;
		
		Object pgpObject = pgpObjectFactory.nextObject();
		
		// the first object might be a PGP marker packet.
		if (pgpObject instanceof PGPEncryptedDataList) {
			
			pgpEncryptedDataList = (PGPEncryptedDataList) pgpObject;
		}
		else {
			
			pgpEncryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
		}
		
		// find the secret key attached to the data
		Iterator<PGPPublicKeyEncryptedData> publicKeyEncryptedDataIterator = pgpEncryptedDataList.getEncryptedDataObjects();
		PGPPrivateKey pgpPrivateKey = null;
		PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
		
		while (pgpPrivateKey == null && publicKeyEncryptedDataIterator.hasNext()) {
			
			publicKeyEncryptedData = publicKeyEncryptedDataIterator.next();
			
			pgpPrivateKey = findPrivateKey(	privateKeyringInputStream,
											publicKeyEncryptedData.getKeyID(),
											passphrase);
		}
		
		if (pgpPrivateKey == null) {
			
			throw new IllegalArgumentException("Secret key for message not found.");
		}
		
		InputStream decryptedDataStream = publicKeyEncryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivateKey));
		
		PGPObjectFactory decryptedDataFactory = new PGPObjectFactory(	decryptedDataStream,
																		keyFingerprintCalculator);
		
		Object decryptedDataObject = decryptedDataFactory.nextObject();
		
		if (decryptedDataObject instanceof PGPCompressedData) {
			
			PGPCompressedData compressedData = (PGPCompressedData) decryptedDataObject;
			PGPObjectFactory decompressedDataFactory = new PGPObjectFactory(compressedData.getDataStream(),
																			keyFingerprintCalculator);
			
			decryptedDataObject = decompressedDataFactory.nextObject();
		}
		
		if (decryptedDataObject instanceof PGPLiteralData) {
			
			PGPLiteralData pgpLiteralData = (PGPLiteralData) decryptedDataObject;
			
			InputStream decompressedDataInputStream = pgpLiteralData.getInputStream();
			FileUtil.copyToOutputStream(decompressedDataInputStream,
										finalOutputStream);
		}
		else if (decryptedDataObject instanceof PGPOnePassSignatureList) {
			
			throw new PGPException("Encrypted message contains a signed message - not literal data.");
		}
		else {
			
			throw new PGPException("Message is not a simple encrypted file - type unknown.");
		}
		
		if (publicKeyEncryptedData.isIntegrityProtected() &&
				!publicKeyEncryptedData.verify()) {
			
			throw new PGPException("Message failed integrity check");
		}
	}
	
	/**
	 * @param out
	 * @param fileName
	 * @param publicKey
	 * @param secretKey
	 * @param password
	 * @param armor
	 * @param withIntegrityCheck
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public static void signEncryptFile(	OutputStream out,
										String fileName,
										PGPPublicKey publicKey,
										PGPSecretKey secretKey,
										String password,
										boolean armor,
										boolean withIntegrityCheck)
			throws Exception {
		
		if (armor) {
			out = new ArmoredOutputStream(out);
		}
		
		BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(DATA_ENCRYPTION_ALGORITHM);
		dataEncryptor.setWithIntegrityPacket(withIntegrityCheck);
		dataEncryptor.setSecureRandom(new SecureRandom());
		
		PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
		encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
		
		OutputStream encryptedOut = encryptedDataGenerator.open(out,
																new byte[PGPCrypto.BUFFER_SIZE]);
		
		// Initialize compressed data generator
		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(DATA_COMPRESSION_ALGORITHM);
		OutputStream compressedOut = compressedDataGenerator.open(	encryptedOut,
																	new byte[PGPCrypto.BUFFER_SIZE]);
		
		// Initialize signature generator
		PGPPrivateKey privateKey = findPrivateKey(	secretKey,
													password.toCharArray());
		
		PGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(	secretKey.getPublicKey().getAlgorithm(),
																				HASH_ALGORITHM);
		
		PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signerBuilder);
		signatureGenerator.init(PGPSignature.BINARY_DOCUMENT,
								privateKey);
		
		boolean firstTime = true;
		Iterator<String> it = (Iterator<String>) secretKey.getPublicKey().getUserIDs();
		while (it.hasNext() && firstTime) {
			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
			spGen.setSignerUserID(	false,
									it.next());
			signatureGenerator.setHashedSubpackets(spGen.generate());
			// Exit the loop after the first iteration
			firstTime = false;
		}
		signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
		
		// Initialize literal data generator
		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
		OutputStream literalOut = literalDataGenerator.open(
															compressedOut,
															PGPLiteralData.BINARY,
															fileName,
															new Date(),
															new byte[PGPCrypto.BUFFER_SIZE]);
		
		// Main loop - read the "in" stream, compress, encrypt and write to the "out" stream
		FileInputStream in = new FileInputStream(fileName);
		byte[] buf = new byte[PGPCrypto.BUFFER_SIZE];
		int len;
		while ((len = in.read(buf)) > 0) {
			literalOut.write(	buf,
								0,
								len);
			signatureGenerator.update(	buf,
										0,
										len);
		}
		
		in.close();
		literalDataGenerator.close();
		// Generate the signature, compress, encrypt and write to the "out" stream
		signatureGenerator.generate().encode(compressedOut);
		compressedDataGenerator.close();
		encryptedDataGenerator.close();
		if (armor) {
			out.close();
		}
	}
	
	/**
	 * @param in
	 * @param keyIn
	 * @param extractContentFile
	 * @return
	 * @throws Exception
	 */
	public static boolean verifyFile(	InputStream in,
										InputStream keyIn,
										String extractContentFile)
			throws Exception {
		
		in = PGPUtil.getDecoderStream(in);
		
		PGPObjectFactory pgpFact = new PGPObjectFactory(in,
														keyFingerprintCalculator);
		PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();
		
		pgpFact = new PGPObjectFactory(	c1.getDataStream(),
										keyFingerprintCalculator);
		
		PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();
		
		PGPOnePassSignature ops = p1.get(0);
		
		PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
		
		InputStream dIn = p2.getInputStream();
		
		FileUtil.copyToOutputStream(dIn,
									new FileOutputStream(extractContentFile));
		
		int ch;
		PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
																			keyFingerprintCalculator);
		
		PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
		
		FileOutputStream out = new FileOutputStream(p2.getFileName());
		
		ops.init(	new BcPGPContentVerifierBuilderProvider(),
					key);
		
		while ((ch = dIn.read()) >= 0) {
			ops.update((byte) ch);
			out.write(ch);
		}
		
		out.close();
		
		PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
		return ops.verify(p3.get(0));
	}
	
}