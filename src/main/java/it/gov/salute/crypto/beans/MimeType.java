package it.gov.salute.crypto.beans;

import java.util.Arrays;

/**
 * @author alessandro.imperio
 *
 */
public class MimeType {
	
	private final String	name;
	private final int[]		sequence;
	private final String	extension;
	
	public MimeType(String name,
					int[] sequence,
					String extension) {
		
		this.name = name;
		this.sequence = sequence;
		this.extension = extension;
	}
	
	public String getName() {
		
		return name;
	}
	
	public int[] getSequence() {
		
		return sequence;
	}
	
	public String getExtension() {
		
		return extension;
	}
	
	public boolean matchByName(String name) {
		
		return this.name != null && this.name.equals(name);
	}
	
	public boolean matchBySequence(int[] sequence) {
		
		return Arrays.equals(	this.sequence,
								sequence);
	}
	
	@Override
	public boolean equals(Object obj) {
		
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		MimeType other = (MimeType) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		}
		else if (!name.equals(other.name))
			return false;
		if (!matchBySequence(other.sequence))
			return false;
		return true;
	}
	
}
