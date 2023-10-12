package it.gov.salute.crypto.engine;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author alessandro.imperio
 *
 */
public abstract class BCCrypto {
	
	private static final BouncyCastleProvider securityProvider;
	
	static {
		
		securityProvider = new BouncyCastleProvider();
		Security.addProvider(securityProvider);
	}
	
	public static Provider getSecurityProvider() {
		
		return securityProvider;
	}
	
}
