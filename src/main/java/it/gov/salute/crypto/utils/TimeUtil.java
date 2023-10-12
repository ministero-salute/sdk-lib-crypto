package it.gov.salute.crypto.utils;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.log4j.Logger;

/**
 * @author alessandro.imperio
 *
 */
public class TimeUtil {
	
	private static final Logger logger = Logger.getLogger(TimeUtil.class);
	
	/**
	 * returns the number of nanoseconds elapsed from the default origin till now
	 * 
	 * @return
	 */
	public static long getStopwatchTime() {
		
		return System.nanoTime();
	}
	
	/**
	 * calculate the time interval (in approximated milliseconds) between current time and the default origin (minus the optional offset)
	 *
	 * @param stopwatchTime
	 * @param operation
	 * @return
	 */
	public static long estimateElapsedTime(	long stopwatchTime,
											String operation) {
		
		long estimatedElapsedTime = Math.round((double) (System.nanoTime() - stopwatchTime) / (1000 * 1000));
		
		if (StringUtils.isNotEmpty(operation)) {
			
			logger.info(LibProperties.getMessageProperty(	"tempo.trascorso.per.operazione",
															operation,
															TimeUtil.formatInterval(estimatedElapsedTime)));
		}
		
		return estimatedElapsedTime;
	}
	
	/**
	 * returns the string representation of a time interval expressed in number of milliseconds
	 * 
	 * @param elapsedTimeInMillis
	 * @return
	 */
	public static String formatInterval(long elapsedTimeInMillis) {
		
		return DurationFormatUtils.formatDurationHMS(elapsedTimeInMillis);
	}
}
