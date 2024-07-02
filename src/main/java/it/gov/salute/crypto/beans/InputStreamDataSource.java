/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.crypto.beans;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.DataSource;

import org.apache.commons.lang3.StringUtils;

import it.gov.salute.crypto.utils.FileUtil;
import it.gov.salute.crypto.utils.MimeUtil;

/**
 * @author alessandro.imperio
 *
 */
public class InputStreamDataSource implements DataSource {
	
	private final String	contentType;
	private final String	name;
	
	private final byte[]	buffer;
	private final int		size;
	
	public InputStreamDataSource(	InputStream inputStream,
									byte[] dataMarker,
									String contentType,
									String name)
			throws IOException {
		
		if (inputStream != null) {
			
			// read data from inputStream source and store it into the internal buffer
			try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();) {
				
				FileUtil.copyToOutputStream(inputStream,
											null,
											byteArrayOutputStream,
											dataMarker);
				this.buffer = byteArrayOutputStream.toByteArray();
				this.size = buffer.length;
				
				if (StringUtils.isNotEmpty(contentType)) {
					
					this.contentType = contentType;
				}
				else {
					
					// extract mime-type bytes from the stored buffer
					byte[] mimeTypeBytes = MimeUtil.isolateMimeTypeBytes(this.buffer);
					
					// guess the mime-type from the isolated bytes
					this.contentType = MimeUtil.guessMimeTypeFromBytes(mimeTypeBytes);
				}
			}
		}
		else {
			
			throw new IllegalArgumentException("inputStream for InputStreamDataSource cannot be null");
		}
		
		this.name = name;
	}
	
	@Override
	public InputStream getInputStream() throws IOException {
		
		return new ByteArrayInputStream(this.buffer);
	}
	
	@Override
	public OutputStream getOutputStream() throws IOException {
		
		throw new UnsupportedOperationException("InputStreamDataSource is a READ-ONLY DataSource implementation");
	}
	
	@Override
	public String getContentType() {
		
		return this.contentType;
	}
	
	@Override
	public String getName() {
		
		return this.name;
	}
	
	public int getSize() {
		
		return this.size;
	}
	
}
