/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.utils;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;

import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.io.ZipInputStream;
import net.lingala.zip4j.model.FileHeader;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;

/**
 * @author alessandro.imperio
 *
 */
public class ZipUtil {
	
	private static final Logger	logger						= Logger.getLogger(ZipUtil.class);
	
	private static final int	DEFAULT_ENCRYPTION_METHOD	= Zip4jConstants.ENC_METHOD_AES;
	// AES_STRENGTH_128 - For both encryption and decryption
	// AES_STRENGTH_192 - For decryption only
	// AES_STRENGTH_256 - For both encryption and decryption
	private static final int	DEFAULT_KEY_STRENGTH		= Zip4jConstants.AES_STRENGTH_256;
	
	/**
	 * initiate Zip Parameters which define various properties
	 * 
	 * @param compressionLevel
	 * @param enableEncryption
	 * @param encryptionPassword
	 * @param encryptionMethod
	 * @param encryptionKeyStrength
	 * @return
	 */
	private static ZipParameters createZipParameters(	int compressionLevel,
														boolean enableEncryption,
														String encryptionPassword,
														int encryptionMethod,
														int encryptionKeyStrength) {
		
		ZipParameters parameters = new ZipParameters();
		
		parameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE);
		
		// DEFLATE_LEVEL_FASTEST - Lowest compression level but higher speed of compression
		// DEFLATE_LEVEL_FAST - Low compression level but higher speed of compression
		// DEFLATE_LEVEL_NORMAL - Optimal balance between compression level/speed
		// DEFLATE_LEVEL_MAXIMUM - High compression level with a compromise of speed
		// DEFLATE_LEVEL_ULTRA - Highest compression level but low speed
		parameters.setCompressionLevel(compressionLevel);
		
		// set the encryption flag
		parameters.setEncryptFiles(enableEncryption);
		
		if (enableEncryption) {
			
			parameters.setEncryptionMethod(encryptionMethod);
			parameters.setAesKeyStrength(encryptionKeyStrength);
			parameters.setPassword(encryptionPassword);
		}
		
		return parameters;
	}
	
	/**
	 * @param compressionLevel
	 * @param enableEncryption
	 * @param encryptionPassword
	 * @return
	 */
	private static ZipParameters createZipParameters(	int compressionLevel,
														boolean enableEncryption,
														String encryptionPassword) {
		
		return createZipParameters(	compressionLevel,
									enableEncryption,
									encryptionPassword,
									DEFAULT_ENCRYPTION_METHOD,
									DEFAULT_KEY_STRENGTH);
	}
	
	/**
	 * @param newZipArchiveFilePath
	 * @param enableEncryption
	 * @param encryptionPassword
	 * @param filesToAddPaths
	 * @throws Exception
	 */
	public static void createZipArchive(String newZipArchiveFilePath,
										boolean enableEncryption,
										String encryptionPassword,
										List<String> filesToAddPaths)
			throws Exception {
		
		try {
			
			ZipFile newZipFile = new ZipFile(newZipArchiveFilePath);
			
			// delete zip archive file(s), if there are already zip files in the same path
			if (newZipFile.getFile().exists()) {
				
				if (!deleteArchiveFiles(newZipFile)) {
					
					throw new RuntimeException(LibProperties.getMessageProperty("eliminazione.file.archivio.fallita"));
				}
			}
			
			ArrayList<File> filesToAdd = new ArrayList<File>();
			
			for (String filePath : filesToAddPaths) {
				
				filesToAdd.add(new File(filePath));
			}
			
			ZipParameters zipParameters = createZipParameters(	Zip4jConstants.DEFLATE_LEVEL_NORMAL,
																enableEncryption,
																encryptionPassword);
			
			newZipFile.addFiles(filesToAdd,
								zipParameters);
		}
		catch (Exception e1) {
			
			logger.error(	"ERROR",
							e1);
			
			try {
				
				// delete zip archive file(s), if there are already zip files in the same path
				ZipFile newZipFile = new ZipFile(newZipArchiveFilePath);
				if (newZipFile.getFile().exists()) {
					
					if (!deleteArchiveFiles(newZipFile)) {
						
						logger.error(LibProperties.getMessageProperty("eliminazione.file.archivio.fallita"));
					}
				}
			}
			catch (Exception e2) {
				
				logger.error(	"ERROR",
								e2);
			}
			
			throw new RuntimeException(LibProperties.getMessageProperty("creazione.file.fallita",
																		newZipArchiveFilePath));
		}
	}
	
	/**
	 * @param zipArchiveFilePath
	 * @param encryptionPassword
	 * @param destinationFolder
	 */
	public static void extractZipArchive(	String zipArchiveFilePath,
											String encryptionPassword,
											String destinationFolder) {
		
		try {
			
			ZipFile zipFile = new ZipFile(zipArchiveFilePath);
			
			if (zipFile.isEncrypted()) {
				
				zipFile.setPassword(encryptionPassword);
			}
			
			zipFile.extractAll(destinationFolder);
		}
		catch (ZipException e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("estrazione.archivio.fallita",
																		zipArchiveFilePath));
		}
	}
	
	/**
	 * delete the file(s) associated with the specified zip file object
	 * returns true if all tha files are correctly deleted, false otherwise
	 * 
	 * @param zipArchiveFile
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static boolean deleteArchiveFiles(ZipFile zipArchiveFile) {
		
		try {
			
			boolean deleteSuccesful = true;
			
			// check if it is a valid zip file
			if (zipArchiveFile.isValidZipFile()) {
				
				ArrayList<String> zipFileList = (ArrayList<String>) zipArchiveFile.getSplitZipFiles();
				
				if (zipFileList != null) {
					
					for (String zipFilePath : zipFileList) {
						
						File file = new File(zipFilePath);
						
						if (!file.delete()) {
							
							logger.warn(LibProperties.getMessageProperty(	"eliminazione.file.fallita",
																			file.getAbsolutePath()));
							deleteSuccesful = false;
						}
					}
				}
			}
			// if it is not a valid zip file, treat it as a simple file
			else {
				
				if (!zipArchiveFile.getFile().delete()) {
					
					logger.warn(LibProperties.getMessageProperty(	"eliminazione.file.fallita",
																	zipArchiveFile.getFile().getAbsolutePath()));
					deleteSuccesful = false;
				}
			}
			
			return deleteSuccesful;
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("eliminazione.file.fallita",
																		zipArchiveFile.getFile().getAbsolutePath()));
		}
	}
	
	/**
	 * delete the file(s) associated with the zip file referenced by the specified path
	 * returns true if all tha files are correctly deleted, false otherwise
	 * 
	 * @param zipArchiveFilePath
	 * @return
	 */
	public static void deleteArchiveFiles(String zipArchiveFilePath) {
		
		try {
			
			deleteArchiveFiles(new ZipFile(zipArchiveFilePath));
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("eliminazione.file.fallita",
																		zipArchiveFilePath));
		}
	}
	
	/**
	 * @param zipArchiveFilePath
	 * @param encryptionPassword
	 * @param deleteZipArchive
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static HashMap<String, byte[]> getFilesFromZipArchive(	String zipArchiveFilePath,
																	String encryptionPassword,
																	boolean deleteZipArchive) {
		
		try {
			
			ZipFile zipFile = new ZipFile(zipArchiveFilePath);
			
			if (zipFile.isEncrypted()) {
				
				zipFile.setPassword(encryptionPassword);
			}
			
			HashMap<String, byte[]> filesMap = new HashMap<String, byte[]>();
			
			List<FileHeader> fileHeaderList = (List<FileHeader>) zipFile.getFileHeaders();
			
			for (FileHeader fileHeader : fileHeaderList) {
				
				if (fileHeader == null) {
					
					continue;
				}
				
				byte[] fileContentByteArray = null;
				
				try (ZipInputStream zipInputStream = zipFile.getInputStream(fileHeader)) {
					
					if (zipInputStream == null) {
						
						logger.warn(LibProperties.getMessageProperty(	"lettura.file.fallita",
																		zipArchiveFilePath.concat(" -> ").concat(fileHeader.getFileName())));
						continue;
					}
					
					fileContentByteArray = FileUtil.copyToByteArray(zipInputStream,
																	(int) fileHeader.getUncompressedSize());
				}
				
				filesMap.put(	fileHeader.getFileName(),
								fileContentByteArray);
			}
			
			// delete zip archive file(s) after having read its content, if requested
			if (deleteZipArchive) {
				
				deleteArchiveFiles(zipFile);
			}
			
			return filesMap;
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty("lettura.file.fallita",
																		zipArchiveFilePath));
		}
	}
	
}
