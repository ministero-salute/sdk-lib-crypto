/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.utils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Stack;
import java.util.regex.Matcher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import it.gov.salute.crypto.constants.HashAlgorithms;

/**
 * @author alessandro.imperio
 *
 */
public class FileUtil {
	
	private static final Logger	logger						= Logger.getLogger(FileUtil.class);
	
	// buffer/chunk size set for reading from/writing on streams (4 kB)
	private static final int	CHUNK_SIZE					= 4 * 1024;
	
	// set of chars used as path separators
	private static final String	SEPARATORS_CHAR_SET			= "\\\\\\/";
	// char used as separator between filename and its extension
	private static final String	EXT_SEPARATOR_CHAR			= ".";
	
	// regular expressions defined for working with paths
	private static final String	FIND_SEPARATORS_REG_EXPR	= "[".concat(SEPARATORS_CHAR_SET).concat("]+");
	private static final String	FIND_EXT_REG_EXPR			= "\\".concat(EXT_SEPARATOR_CHAR).concat("(?=[^\\").concat(EXT_SEPARATOR_CHAR).concat("]+$)");
	private static final String	FIND_FILENAME_REG_EXPR		= "[".concat(SEPARATORS_CHAR_SET).concat("]+(?=[^").concat(SEPARATORS_CHAR_SET).concat("]+$)");
	
	// Java platform natively supported algorithms -> MD5, SHA-1, SHA-256
	private static final String	HASH_ALGORITHM				= HashAlgorithms.MD5;
	
	public enum HashEncoding {
		HEX, BASE64
	};
	
	/**
	 * @param inputStream
	 * @param byteArrayCapacity
	 * @return
	 * @throws IOException
	 */
	public static byte[] copyToByteArray(	InputStream inputStream,
											int byteArrayCapacity)
			throws IOException {
		
		// intrinsec byte array capacity limit to int max value -> ~ 2 GB
		byte[] outputByteArray = new byte[byteArrayCapacity];
		
		byte[] buffer = new byte[CHUNK_SIZE];
		int bufferPointer = 0;
		int bytesRead = -1;
		
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			
			System.arraycopy(	buffer,
								0,
								outputByteArray,
								bufferPointer,
								bytesRead);
			bufferPointer += bytesRead;
		}
		
		return outputByteArray;
	}
	
	/**
	 * @param inputStream
	 * @param encoding
	 * @param charArrayCapacity
	 * @return
	 * @throws Exception
	 */
	private static char[] copyToCharArray(	InputStream inputStream,
											Charset encoding,
											int charArrayCapacity)
			throws Exception {
		
		try (InputStreamReader inputStreamReader = new InputStreamReader(	inputStream,
																			encoding);) {
			
			// intrinsec char array capacity limit to int max value -> ~ 2 GB
			char[] outputCharArray = new char[charArrayCapacity];
			
			char[] charBuffer = new char[CHUNK_SIZE];
			int bufferPointer = 0;
			int charsRead = -1;
			
			while ((charsRead = inputStreamReader.read(charBuffer)) != -1) {
				
				System.arraycopy(	charBuffer,
									0,
									outputCharArray,
									bufferPointer,
									charsRead);
				bufferPointer += charsRead;
			}
			
			return outputCharArray;
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw e;
		}
	}
	
	/**
	 * @param inputStream
	 * @param outputStream
	 * @return
	 * @throws IOException
	 */
	public static <T extends OutputStream> void copyToOutputStream(	InputStream inputStream,
																	T outputStream)
			throws IOException {
		
		copyToOutputStream(	inputStream,
							outputStream,
							0);
	}
	
	/**
	 * 
	 * @param inputStream
	 * @param outputStream
	 * @param startIndex
	 *            indice del byte dal quale partire con la copia (i precedenti verranno scartati)
	 * @throws IOException
	 */
	public static <T extends OutputStream> void copyToOutputStream(	InputStream inputStream,
																	T outputStream,
																	int startIndex)
			throws IOException {
		
		byte[] buffer = new byte[CHUNK_SIZE];
		int bytesRead = -1;
		int bufferPointer = 0;
		int bytesOffset = 0;
		boolean startingChunkPassed = false;
		boolean canCopy = false;
		
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			
			bufferPointer += bytesRead;
			
			if (!startingChunkPassed &&
					bufferPointer >= startIndex) {
				
				canCopy = true;
				
				// se il puntatore non ha ancora superato il chunk nel quale verr� letto il byte iniziale
				if (bufferPointer <= NumberUtil.calcolaProssimoMultiplo(startIndex,
																		CHUNK_SIZE)) {
					
					// calcola offset come modulo tra startIndex e la dimensione del buffer
					bytesOffset = startIndex % CHUNK_SIZE;
				}
				else {
					
					bytesOffset = 0;
					startingChunkPassed = true;
				}
			}
			
			if (canCopy) {
				
				outputStream.write(	buffer,
									bytesOffset,
									bytesRead - bytesOffset);
			}
		}
		outputStream.flush();
	}
	
	/**
	 * inizializza una pila (eventualmente resettandola) inserendo gli elementi dell'array specificato in ordine inverso
	 * (elemento in cima = primo elemento dell'array)
	 * 
	 * @param stack
	 * @param array
	 */
	private static void initStackFromArray(	Stack<Byte> stack,
											byte[] array) {
		
		if (stack != null) {
			
			stack.clear();
			
			for (int i = array.length - 1; i >= 0; i--) {
				
				stack.push(array[i]);
			}
		}
	}
	
	/**
	 * @param inputStream
	 * @param markerToFind
	 * @param outputStream
	 * @param markerToInsert
	 * @throws IOException
	 */
	public static <T extends OutputStream> void copyToOutputStream(	InputStream inputStream,
																	byte[] markerToFind,
																	T outputStream,
																	byte[] markerToInsert)
			throws IOException {
		
		if (markerToInsert != null &&
				markerToInsert.length > 0) {
			
			outputStream.write(markerToInsert);
		}
		
		byte[] buffer = new byte[CHUNK_SIZE];
		int bytesRead = -1;
		int bufferPointer = 0;
		int bytesOffset = 0;
		boolean searchForMarker = markerToFind != null &&
				markerToFind.length > 0;
		boolean markerMatch = false;
		boolean markerChunkPassed = false;
		boolean canCopy = !searchForMarker;
		
		Stack<Byte> byteStack = null;
		int byteIndex = 0;
		int lastMarkerByteIndex = -1;
		
		if (searchForMarker) {
			
			byteStack = new Stack<Byte>();
			initStackFromArray(	byteStack,
								markerToFind);
		}
		
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			
			if (searchForMarker && !markerMatch) {
				
				for (byteIndex = 0; byteIndex < CHUNK_SIZE; byteIndex++) {
					
					// se il byte letto � uguale al byte in testa alla pila per il confronto
					if (byteStack.peek() == buffer[byteIndex]) {
						
						// rimuovi l'elemento trovato dalla pila
						byteStack.pop();
						
						// se la pila risulta completamente svuotata, significa che � stata identificata una sequenza completa
						if (byteStack.size() == 0) {
							
							lastMarkerByteIndex = bufferPointer + byteIndex;
							markerMatch = true;
							canCopy = true;
							break;
						}
					}
					// se il confronto ha dato esito negativo, e la pila aveva gi� iniziato ad essere consumata
					else if (byteStack.size() < markerToFind.length) {
						
						// reinizializza la pila
						initStackFromArray(	byteStack,
											markerToFind);
					}
				}
			}
			
			bufferPointer += bytesRead;
			
			// se � stata condotta una ricerca di un marker
			// ..e se � stato trovato il marker
			// ..e se non � stato ancora superato il primo chunk da cui leggere (quello contenente il marker)
			if (searchForMarker &&
					markerMatch &&
					!markerChunkPassed) {
				
				// se il puntatore non ha ancora superato il chunk contenente il marker
				if (bufferPointer <= NumberUtil.calcolaProssimoMultiplo(lastMarkerByteIndex,
																		CHUNK_SIZE)) {
					
					// calcola offset come modulo tra il byte successivo all'ultimo del marker e la dimensione del buffer
					bytesOffset = (lastMarkerByteIndex + 1) % CHUNK_SIZE;
				}
				else {
					
					bytesOffset = 0;
					markerChunkPassed = true;
				}
			}
			
			if (canCopy) {
				
				outputStream.write(	buffer,
									bytesOffset,
									bytesRead - bytesOffset);
			}
		}
		outputStream.flush();
	}
	
	/**
	 * @param string
	 * @param outputStream
	 * @param encoding
	 * @throws IOException
	 */
	private static <T extends OutputStream> void writeToOutputStream(	String string,
																		T outputStream,
																		Charset encoding)
			throws IOException {
		
		try (StringReader stringReader = new StringReader(string);
				OutputStreamWriter outputStreamWriter = new OutputStreamWriter(	outputStream,
																				encoding);) {
			
			char[] charBuffer = new char[CHUNK_SIZE];
			int charsRead = -1;
			while ((charsRead = stringReader.read(charBuffer)) != -1) {
				
				outputStreamWriter.write(	charBuffer,
											0,
											charsRead);
			}
			outputStreamWriter.flush();
		}
		
	}
	
	/**
	 * @param byteArray
	 * @param outputStream
	 * @throws IOException
	 */
	public static <T extends OutputStream> void copyBytesToOutputStream(byte[] byteArray,
																		T outputStream)
			throws IOException {
		
		try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new ByteArrayInputStream(byteArray))) {
			
			byte[] buffer = new byte[CHUNK_SIZE];
			int bytesRead = -1;
			while ((bytesRead = bufferedInputStream.read(buffer)) != -1) {
				
				outputStream.write(	buffer,
									0,
									bytesRead);
			}
			outputStream.flush();
		}
		
	}
	
	/**
	 * @param filePath
	 * @param isRelativePath
	 * @return
	 */
	private static File getFileFromPath(String filePath,
										boolean isRelativePath) {
		
		try {
			
			File file = null;
			
			if (isRelativePath) {
				
				file = new File(LibProperties.class.getClassLoader().getResource(filePath).getFile());
			}
			else {
				
				file = new File(filePath);
			}
			
			return file;
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw e;
		}
	}
	
	/**
	 * @param filePath
	 * @param isRelativePath
	 * @return
	 * @throws Exception
	 */
	public static byte[] readFile(	String filePath,
									boolean isRelativePath)
			throws Exception {
		
		try {
			
			File fileToRead = getFileFromPath(	filePath,
												isRelativePath);
			
			try (InputStream inputStream = new FileInputStream(fileToRead)) {
				
				return copyToByteArray(	inputStream,
										(int) fileToRead.length());
			}
			catch (Exception e) {
				
				throw e;
			}
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw e;
		}
	}
	
	/**
	 * @param filePath
	 * @param isRelativePath
	 * @param encoding
	 * @return
	 * @throws Exception
	 */
	public static String readTextFile(	String filePath,
										boolean isRelativePath,
										Charset encoding)
			throws Exception {
		
		if (encoding == null)
			encoding = EncodingUtil.DEFAULT_CHARSET;
		
		try {
			
			File fileToRead = getFileFromPath(	filePath,
												isRelativePath);
			
			try (InputStream inputStream = new FileInputStream(fileToRead)) {
				
				return new String(copyToCharArray(	inputStream,
													encoding,
													(int) fileToRead.length()));
			}
			catch (Exception e) {
				
				throw e;
			}
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw e;
		}
	}
	
	/**
	 * @param filePath
	 * @param fileContent
	 * @throws Exception
	 */
	public static void writeFile(	String filePath,
									byte[] fileContent)
			throws Exception {
		
		try (FileOutputStream fileOutputStream = new FileOutputStream(new File(filePath));
				BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);) {
			
			copyToOutputStream(	new ByteArrayInputStream(fileContent),
								bufferedOutputStream);
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw e;
		}
	}
	
	/**
	 * @param filePath
	 * @param textFileContent
	 * @param encoding
	 * @throws Exception
	 */
	public static void writeTextFile(	String filePath,
										String textFileContent,
										Charset encoding)
			throws Exception {
		
		try (FileOutputStream fileOutputStream = new FileOutputStream(new File(filePath));) {
			
			writeToOutputStream(textFileContent,
								fileOutputStream,
								encoding);
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw e;
		}
	}
	
	public static String replicateXmlContent(	String fileToCopyPath,
												int numberOfCopies,
												String fileCopyName,
												String newFileRootTag)
			throws Exception {
		
		byte[] fileContent = FileUtil.readFile(	fileToCopyPath,
												false);
		
		String fileCopyPath = FileUtil.getParentFolderFromPath(fileToCopyPath).concat(fileCopyName);
		
		try (FileOutputStream fileOutputStream = new FileOutputStream(new File(fileCopyPath));
				BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);) {
			
			FileUtil.copyToOutputStream(new ByteArrayInputStream(new String("<" + newFileRootTag + ">").getBytes()),
										bufferedOutputStream);
			
			for (int i = 0; i < numberOfCopies; i++) {
				
				FileUtil.copyToOutputStream(new ByteArrayInputStream(fileContent),
											bufferedOutputStream);
			}
			
			FileUtil.copyToOutputStream(new ByteArrayInputStream(new String("</" + newFileRootTag + ">").getBytes()),
										bufferedOutputStream);
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw e;
		}
		
		return fileCopyPath;
	}
	
	/**
	 * @param fileNameWithExtension
	 * @return
	 */
	public static String getFileName(String fileNameWithExtension) {
		
		// separa nome dall'estensione
		String[] tokens = fileNameWithExtension.split(FIND_EXT_REG_EXPR);
		// restituisce il nome ottenuto privo dell'estensione originaria
		return tokens[0];
	}
	
	/**
	 * @param fileNameWithExtension
	 * @return
	 */
	public static String getFileExtension(String fileNameWithExtension) {
		
		// separa nome dall'estensione
		String[] tokens = fileNameWithExtension.split(FIND_EXT_REG_EXPR);
		// restituisce l'estensione
		if (tokens.length == 1)
			return null;
		else
			return tokens[1];
	}
	
	/**
	 * @param fileNameWithExtension
	 * @return
	 */
	public static String changeFileExtension(	String fileNameWithExtension,
												String newExtension) {
		
		// separa nome dall'estensione
		String[] tokens = fileNameWithExtension.split(FIND_EXT_REG_EXPR);
		// restituisce l'estensione
		return tokens[0].concat(EXT_SEPARATOR_CHAR).concat(newExtension);
	}
	
	/**
	 * @param fileNameWithExtension
	 * @param suffix
	 * @return
	 */
	public static String addSuffixToFileName(	String fileNameWithExtension,
												String suffix) {
		
		// separa nome dall'estensione
		String[] tokens = fileNameWithExtension.split(FIND_EXT_REG_EXPR);
		// restituisce il nome privato dell'estensione
		return tokens[0].concat(suffix).concat(EXT_SEPARATOR_CHAR).concat((tokens.length > 1) ? tokens[1] : "");
	}
	
	/**
	 * @param filePath
	 * @return
	 */
	public static String cleanFilePath(String filePath) {
		
		return cleanFilePath(	filePath,
								null,
								false);
	}
	
	/**
	 * @param filePath
	 * @param pathSeparator
	 * @param isRemotePath
	 * @return
	 */
	public static String cleanFilePath(	String filePath,
										String pathSeparator,
										boolean isRemotePath) {
		
		if (filePath == null)
			return null;
		
		if (pathSeparator == null) {
			
			pathSeparator = File.separator;
		}
		
		// se si tratta di percorso locale
		if (!isRemotePath) {
			
			return filePath.replaceAll(	FIND_SEPARATORS_REG_EXPR,
										Matcher.quoteReplacement(pathSeparator));
		}
		// se si tratta di un percorso remoto, non considera i primi 2 caratteri nel processo di sostituzione dei separatori
		else {
			
			return filePath.substring(	0,
										2)
					.concat(filePath.substring(2).replaceAll(	FIND_SEPARATORS_REG_EXPR,
																Matcher.quoteReplacement(pathSeparator)));
		}
	}
	
	/**
	 * @param filePath
	 * @return
	 */
	public static String getParentFolderFromPath(String filePath) {
		
		return getParentFolderFromPath(	filePath,
										null,
										false);
	}
	
	/**
	 * @param filePath
	 * @param pathSeparator
	 * @param isRemotePath
	 * @return
	 */
	public static String getParentFolderFromPath(	String filePath,
													String pathSeparator,
													boolean isRemotePath) {
		
		if (pathSeparator == null) {
			
			pathSeparator = File.separator;
		}
		
		String[] tokens = filePath.split(FIND_FILENAME_REG_EXPR);
		return cleanFilePath(	tokens[0],
								pathSeparator,
								isRemotePath).concat(pathSeparator);
	}
	
	/**
	 * @param filePath
	 * @return
	 */
	public static String getFileNameFromPath(String filePath) {
		
		String[] tokens = filePath.split(FIND_FILENAME_REG_EXPR);
		if (tokens.length == 1)
			return null;
		else
			return tokens[tokens.length - 1];
	}
	
	/**
	 * @param fileName
	 * @param folderPath
	 * @param subFolders
	 * @return
	 */
	public static String buildFilePath(	String fileName,
										String folderPath,
										String... subFolders) {
		
		return buildFilePath(	fileName,
								null,
								false,
								folderPath,
								subFolders);
	}
	
	/**
	 * @param fileName
	 * @param pathSeparator
	 * @param isRemotePath
	 * @param folderPath
	 * @param subFolders
	 * @return
	 */
	public static String buildFilePath(	String fileName,
										String pathSeparator,
										boolean isRemotePath,
										String folderPath,
										String... subFolders) {
		
		if (pathSeparator == null) {
			
			pathSeparator = File.separator;
		}
		
		if (StringUtils.isNotEmpty(folderPath)) {
			
			folderPath = cleanFilePath(	folderPath,
										pathSeparator,
										isRemotePath);
			// ensure that the folder path ends with a separator
			if (!String.valueOf(folderPath.charAt(folderPath.length() - 1)).matches(FIND_SEPARATORS_REG_EXPR)) {
				
				folderPath = folderPath.concat(pathSeparator);
			}
		}
		else {
			
			folderPath = "";
		}
		
		StringBuilder newPathBuilder = new StringBuilder(folderPath);
		
		for (String folder : subFolders) {
			
			if (StringUtils.isNotEmpty(folder)) {
				
				newPathBuilder.append(folder);
				newPathBuilder.append(pathSeparator);
			}
		}
		
		if (StringUtils.isNotEmpty(fileName)) {
			
			newPathBuilder.append(fileName);
		}
		
		return newPathBuilder.toString();
	}
	
	/**
	 * @param filePath
	 * @return
	 */
	public static long getFileSize(String filePath) {
		
		return new File(filePath).length();
	}
	
	/**
	 * @param content
	 * @param hashEncoding
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String getMD5Hash(byte[] content,
									HashEncoding hashEncoding)
			throws NoSuchAlgorithmException {
		
		MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM);
		messageDigest.update(content);
		byte[] hashBytes = messageDigest.digest();
		
		switch (hashEncoding) {
			
			default:
			case HEX:
				
				return EncodingUtil.bytesToHexString(hashBytes);
			
			case BASE64:
				
				return Base64.encodeBase64String(hashBytes);
		}
	}
	
	/**
	 * @param content
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String getMD5Hash(byte[] content) throws NoSuchAlgorithmException {
		
		return getMD5Hash(	content,
							HashEncoding.HEX);
	}
	
	public static boolean deleteFileOrDirectory(String filePath,
												boolean recursiveDelete) {
		
		File fileToDelete = new File(filePath);
		
		try {
			
			boolean deleteSuccesful = true;
			
			if (fileToDelete.exists()) {
				
				// if the file specified is a directory
				if (fileToDelete.isDirectory()) {
					
					// find if it's empty
					File[] directoryFiles = fileToDelete.listFiles();
					
					boolean isDirectoryEmpty = directoryFiles == null || directoryFiles.length == 0;
					
					// if the directory contains other files/directories
					if (!isDirectoryEmpty) {
						
						// if is requested to delete recursively
						if (recursiveDelete) {
							
							for (File directoryFile : directoryFiles) {
								
								deleteSuccesful = deleteSuccesful && deleteFileOrDirectory(	directoryFile.getAbsolutePath(),
																							recursiveDelete);
							}
						}
						// else if it is NOT requested to delete recursively
						else {
							
							logger.warn(LibProperties.getMessageProperty(	"eliminazione.cartella.fallita.non.vuota",
																			fileToDelete.getAbsolutePath()));
							deleteSuccesful = false;
						}
					}
					// if the directory contained other files/directories and their deletion has been confirmed
					// ..or if the directory did not contain other files/directories in the first place
					if ((!isDirectoryEmpty && deleteSuccesful) ||
							isDirectoryEmpty) {
						
						if (!fileToDelete.delete()) {
							
							logger.warn(LibProperties.getMessageProperty(	"eliminazione.cartella.fallita",
																			fileToDelete.getAbsolutePath()));
							deleteSuccesful = false;
						}
					}
				}
				// if it's a simple file
				else {
					
					if (!fileToDelete.delete()) {
						
						logger.warn(LibProperties.getMessageProperty(	"eliminazione.file.fallita",
																		fileToDelete.getAbsolutePath()));
					}
				}
			}
			
			return deleteSuccesful;
		}
		catch (Exception e) {
			
			logger.error(	"ERROR",
							e);
			throw new RuntimeException(LibProperties.getMessageProperty((fileToDelete.isFile()) ? "eliminazione.file.fallita" : "eliminazione.cartella.fallita",
																		filePath));
		}
	}
	
}
