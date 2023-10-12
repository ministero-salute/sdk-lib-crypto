package it.gov.salute.crypto.constants;

import it.gov.salute.crypto.beans.MimeType;

/**
 * @author alessandro.imperio
 *
 *         mime types for signed files / encrypted files / keys / ecc..
 *
 */
public interface MimeTypes {
	
	// size (in bytes) of the chunk of data which represent the mime-type
	public final int		SIZE				= 16;
	
	public final MimeType	BINARY				= new MimeType(	"application/octet-stream",
																null,
																null);
	
	// S-MIME signed data
	
	// for retro-compatibility
	public final MimeType	X_PKCS7_SIGNATURE	= new MimeType(	"application/x-pkcs7-signature",
																null,
																"p7s");
	public final MimeType	PKCS7_SIGNATURE		= new MimeType(	"application/pkcs7-signature",
																null,
																"p7s");
	
	// S-MIME enveloped data
	
	// for retro-compatibility
	public final MimeType	X_PKCS7_DATA		= new MimeType(	"application/x-pkcs7-mime",
																null,
																"p7m");
	public final MimeType	PKCS7_DATA			= new MimeType(	"application/pkcs7-mime",
																new int[] {
																		0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03, 0xA0, 0x80, 0x30
																},
																"p7m");
}
