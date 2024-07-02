/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.engine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import javax.activation.DataHandler;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimeUtility;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;

import it.gov.salute.crypto.beans.InputStreamDataSource;
import it.gov.salute.crypto.constants.ContentEncodings;
import it.gov.salute.crypto.constants.MimeTypes;
import it.gov.salute.crypto.constants.SignatureAlgorithms;
import it.gov.salute.crypto.utils.CryptoUtil;
import it.gov.salute.crypto.utils.EncodingUtil;
import it.gov.salute.crypto.utils.FileUtil;
import it.gov.salute.crypto.utils.LibProperties;

/**
 * @author alessandro.imperio
 *
 *         with a bit of magic (against the principle of least astonishment)
 * 
 *         Note: use org.bouncycastle.mail.smime.SMIMEUtil methods to manipulate Objects such MimeMessage, MimeMultipart and MimeBodyPart
 *
 */
public final class SMIMECrypto extends BCCrypto {
	
	private static final Logger					logger	= Logger.getLogger(SMIMECrypto.class);
	
	private static final String					SIGNATURE_ALGORITHM;
	private static final ASN1ObjectIdentifier	ENCRYPTION_ALGORITHM;
	
	private static final byte[]					DATA_MARKER;
	
	static {
		
		SIGNATURE_ALGORITHM = SignatureAlgorithms.SHA1_RSA;
		ENCRYPTION_ALGORITHM = CMSAlgorithm.AES256_CBC;
		
		Charset encoding = EncodingUtil.DEFAULT_CHARSET;
		DATA_MARKER = LibProperties.getConfigurationProperty("data.marker").getBytes(encoding);
	}
	
	/**
	 * @param dataInputStream
	 * @param dataMarker
	 * @param contentType
	 * @param contentEncoding
	 * @return
	 * @throws MessagingException
	 * @throws IOException
	 */
	private static MimeMessage encapsulateData(	InputStream dataInputStream,
												byte[] dataMarker,
												String contentType,
												String contentEncoding)
			throws MessagingException, IOException {
		
		Properties props = System.getProperties();
		Session session = Session.getDefaultInstance(	props,
														null);
		MimeMessage mimeData = new MimeMessage(session);
		
		InputStreamDataSource dataSource = new InputStreamDataSource(	dataInputStream,
																		dataMarker,
																		contentType,
																		null);
		
		mimeData.setDataHandler(new DataHandler(dataSource));
		
		String mimeType = null;
		if (StringUtils.isNotEmpty(contentType)) {
			
			mimeType = contentType;
		}
		else {
			
			mimeType = dataSource.getContentType();
		}
		mimeData.setHeader(	"Content-Type",
							mimeType);
		
		String mimeContentEncoding = null;
		if (StringUtils.isNotEmpty(contentEncoding)) {
			
			mimeContentEncoding = contentEncoding;
		}
		else {
			
			// default content transfer encoding
			mimeContentEncoding = ContentEncodings.BINARY;
		}
		mimeData.setHeader(	"Content-Transfer-Encoding",
							mimeContentEncoding);
		
		mimeData.saveChanges();
		
		return mimeData;
	}
	
	public static List<BodyPart> extractBodyParts(MimeMultipart multipartData) throws MessagingException {
		
		List<BodyPart> bodyParts = new ArrayList<BodyPart>();
		
		for (int i = 0; i < multipartData.getCount(); i++) {
			
			bodyParts.add(multipartData.getBodyPart(i));
		}
		
		return bodyParts;
	}
	
	/**
	 * cifra i dati senza firmarli (con codifica di output base64)
	 * 
	 * @param dataToEncryptInputStream
	 * @param encryptionCertificateInputStream
	 * @param encryptedDataOutputStream
	 * @throws IOException
	 * @throws CertificateException
	 * @throws CMSException
	 * @throws SMIMEException
	 * @throws MessagingException
	 * @throws OperatorCreationException
	 */
	public static void cifraFile(	InputStream dataToEncryptInputStream,
									InputStream encryptionCertificateInputStream,
									OutputStream encryptedDataOutputStream)
			throws CertificateException, IOException, OperatorCreationException, MessagingException, SMIMEException, CMSException {
		
		X509Certificate encryptionCertificate = CryptoUtil.getX509CertificateFromStream(encryptionCertificateInputStream);
		
		signAndEncryptData(	dataToEncryptInputStream,
							encryptionCertificate,
							null,
							encryptedDataOutputStream,
							true);
	}
	
	/**
	 * @param dataToEncryptInputStream
	 * @param encryptionCertificate
	 * @param privateKey
	 * @param encryptedDataOutputStream
	 * @param base64Output
	 * @throws MessagingException
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws OperatorCreationException
	 * @throws SMIMEException
	 * @throws CMSException
	 */
	public static void signAndEncryptData(	InputStream dataToEncryptInputStream,
											X509Certificate encryptionCertificate,
											PrivateKey privateKey,
											OutputStream encryptedDataOutputStream,
											boolean base64Output)
			throws MessagingException, IOException, CertificateEncodingException, OperatorCreationException, SMIMEException, CMSException {
		
		MimeMessage mimeData = encapsulateData(	dataToEncryptInputStream,
												DATA_MARKER,
												MimeTypes.BINARY.getName(),
												ContentEncodings.BINARY);
		
		// se è presente una chiave privata, la utilizza per firmare i dati prima della cifratura
		// viceversa, procede alla cifratura lasciando i dati non firmati
		if (privateKey != null) {
			
			// sign data
			MimeMultipart signedData = signData(mimeData,
												privateKey,
												encryptionCertificate);
			
			mimeData.setContent(signedData);
			mimeData.saveChanges();
		}
		
		// encrypt data
		MimeBodyPart encryptedData = encryptData(	mimeData,
													encryptionCertificate);
		
		mimeData.setContent(encryptedData.getContent(),
							encryptedData.getContentType());
		mimeData.saveChanges();
		
		// *** for testing purposes ***
		// encryptedData.saveFile(new File(<.p7m file path>));
		
		OutputStream destinationOutputStream = null;
		
		if (base64Output) {
			
			destinationOutputStream = MimeUtility.encode(	encryptedDataOutputStream,
															ContentEncodings.BASE64);
		}
		else {
			
			destinationOutputStream = encryptedDataOutputStream;
		}
		
		FileUtil.copyToOutputStream(mimeData.getInputStream(),
									destinationOutputStream);
	}
	
	/**
	 * secondo standard PKCS7 (signature)
	 * mime-type: multipart/signed; protocol="application/pkcs7-signature"; micalg=<signature-algorithm>;
	 * 
	 * @param dataToSign
	 * @param privateKey
	 * @param signerCertificate
	 * @return
	 * @throws CertificateEncodingException
	 * @throws OperatorCreationException
	 * @throws SMIMEException
	 */
	private static MimeMultipart signData(	MimeMessage dataToSign,
											PrivateKey privateKey,
											X509Certificate signerCertificate)
			throws CertificateEncodingException, OperatorCreationException, SMIMEException {
		
		SMIMESignedGenerator signedGenerator = new SMIMESignedGenerator();
		SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder().setProvider(getSecurityProvider()).build(	SIGNATURE_ALGORITHM,
																																		privateKey,
																																		signerCertificate);
		
		signedGenerator.addSignerInfoGenerator(signerInfoGenerator);
		
		JcaCertStore certStore = CryptoUtil.createJcaCertStore(signerCertificate);
		signedGenerator.addCertificates(certStore);
		
		return signedGenerator.generate(dataToSign);
	}
	
	/**
	 * secondo standard PKCS7 (enveloped-data)
	 * mime-type: application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data
	 * 
	 * @param dataToEncrypt
	 * @param encryptionCertificate
	 * @return
	 * @throws CertificateEncodingException
	 * @throws CMSException
	 * @throws SMIMEException
	 */
	private static MimeBodyPart encryptData(MimeMessage dataToEncrypt,
											X509Certificate encryptionCertificate)
			throws CertificateEncodingException, CMSException, SMIMEException {
		
		SMIMEEnvelopedGenerator envelopedGenerator = new SMIMEEnvelopedGenerator();
		JceKeyTransRecipientInfoGenerator keyTransRecipientInfoGenerator = new JceKeyTransRecipientInfoGenerator(encryptionCertificate).setProvider(getSecurityProvider());
		
		envelopedGenerator.addRecipientInfoGenerator(keyTransRecipientInfoGenerator);
		
		OutputEncryptor outputEncryptor = new JceCMSContentEncryptorBuilder(ENCRYPTION_ALGORITHM)
				.setProvider(getSecurityProvider()).build();
		
		return envelopedGenerator.generate(	dataToEncrypt,
											outputEncryptor);
	}
	
	/**
	 * decifra i dati saltando il processo di verifica della firma
	 * 
	 * @param dataToDecryptInputStream
	 * @param privateKeyInputStream
	 * @param decryptedDataOutputStream
	 * @throws IOException
	 * @throws CMSException
	 * @throws MessagingException
	 */
	public static void decifraFile(	InputStream dataToDecryptInputStream,
									InputStream privateKeyInputStream,
									OutputStream decryptedDataOutputStream)
			throws IOException, MessagingException, CMSException {
		
		PrivateKey privateKey = CryptoUtil.getPrivateKeyFromStream(privateKeyInputStream);
		
		decryptAndVerifyData(	dataToDecryptInputStream,
								null,
								privateKey,
								decryptedDataOutputStream,
								true);
	}
	
	/**
	 * @param dataToDecryptInputStream
	 * @param encryptionCertificate
	 * @param privateKey
	 * @param decryptedDataOutputStream
	 * @param base64Input
	 * @throws MessagingException
	 * @throws IOException
	 * @throws CMSException
	 */
	public static void decryptAndVerifyData(InputStream dataToDecryptInputStream,
											X509Certificate encryptionCertificate,
											PrivateKey privateKey,
											OutputStream decryptedDataOutputStream,
											boolean base64Input)
			throws MessagingException, IOException, CMSException {
		
		InputStream sourceInputStream = null;
		
		if (base64Input) {
			
			sourceInputStream = MimeUtility.decode(	dataToDecryptInputStream,
													ContentEncodings.BASE64);
		}
		else {
			
			sourceInputStream = dataToDecryptInputStream;
		}
		
		MimeMessage encryptedData = encapsulateData(sourceInputStream,
													null,
													null,
													null);
		
		InputStreamDataSource encryptedDataSource = (InputStreamDataSource) encryptedData.getDataHandler().getDataSource();
		
		if (encryptedDataSource.getSize() > 0 &&
				encryptedDataSource.getContentType().equals(MimeTypes.PKCS7_DATA.getName())) {
			
			JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(privateKey).setProvider(getSecurityProvider());
			
			SMIMEEnveloped smimeEnveloped = new SMIMEEnveloped(encryptedData);
			RecipientInformationStore recipientInfos = smimeEnveloped.getRecipientInfos();
			
			RecipientInformation recipientInfo = null;
			
			// se è stato specificato un certificato, valida le informazioni del destinatario sulla base dei dati in esso contenuti
			if (encryptionCertificate != null) {
				
				RecipientId recipientId = new JceKeyTransRecipientId(encryptionCertificate);
				recipientInfo = recipientInfos.get(recipientId);
			}
			// viceversa, recupera le info del destinatario assumendo che siano valide
			else {
				
				Collection<RecipientInformation> recipients = recipientInfos.getRecipients();
				for (RecipientInformation recipientInformation : recipients) {
					
					if (recipientInformation != null) {
						
						recipientInfo = recipientInformation;
						break;
					}
				}
			}
			
			// se non è stato possibile recuperare le info sul destinatario
			if (recipientInfo == null) {
				
				throw new RuntimeException(LibProperties.getMessageProperty("errore.info.destinatario.messaggio.cifrato.non.presenti"));
			}
			
			// decifra il contenuto e contestualmente lo scrive sull'output stream specificato
			FileUtil.copyToOutputStream(recipientInfo.getContentStream(recipient).getContentStream(),
										DATA_MARKER,
										decryptedDataOutputStream,
										null);
		}
		else {
			
			logger.warn(LibProperties.getMessageProperty("warning.contenuto.non.valido"));
		}
	}
	
}
