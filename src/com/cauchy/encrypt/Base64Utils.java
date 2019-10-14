package com.cauchy.encrypt;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

/**
 * @date 2019-10-14
 * @author Cauchy
 *
 */
public class Base64Utils {

	/**
	 * @description Base64编码
	 * @param plainString
	 * @return encodedString
	 * @throws UnsupportedEncodingException
	 */
	public static String encodeWithBase64(String plainString) throws UnsupportedEncodingException {
		Base64.Encoder encoder = Base64.getEncoder();
		byte[] stringByte = plainString.getBytes("UTF-8");
		String encodedString = encoder.encodeToString(stringByte);
		return encodedString;
	}

	/**
	 * @description Base64解码
	 * @param edcodedString
	 * @return plaintest
	 * @throws UnsupportedEncodingException
	 */
	public static String decodeWithBase64(String edcodedString) throws UnsupportedEncodingException {
		Base64.Decoder decoder = Base64.getDecoder();
		return new String(decoder.decode(edcodedString), "UTF-8");
	}
}
