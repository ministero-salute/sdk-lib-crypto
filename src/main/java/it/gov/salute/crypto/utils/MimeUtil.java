package it.gov.salute.crypto.utils;

import org.apache.log4j.Logger;

import it.gov.salute.crypto.constants.MimeTypes;

/**
 * @author alessandro.imperio
 *
 */
public class MimeUtil {
	
	private static final Logger logger = Logger.getLogger(MimeUtil.class);
	
	public static byte[] isolateMimeTypeBytes(byte[] data) {
		
		byte[] mimeTypeBytes = new byte[MimeTypes.SIZE];
		System.arraycopy(	data,
							0,
							mimeTypeBytes,
							0,
							MimeTypes.SIZE);
		
		logger.debug(EncodingUtil.bytesToReadableHexString(mimeTypeBytes));
		
		return mimeTypeBytes;
	}
	
	public static String guessMimeTypeFromBytes(byte[] mimeTypeBytes) {
		
		int[] mimeTypeInts = EncodingUtil.bytesToInts(mimeTypeBytes);
		
		if (MimeTypes.PKCS7_DATA.matchBySequence(mimeTypeInts)) {
			
			return MimeTypes.PKCS7_DATA.getName();
		}
		else {
			
			return MimeTypes.BINARY.getName();
		}
		
	}
}
