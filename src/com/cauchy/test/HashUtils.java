package com.cauchy.test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtils {
	private static final char[] HEX_DIGITS = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	/**
	 * @description MD5计算散列
	 */
	public static String getMD5String(String data) {
		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		messageDigest.update(data.getBytes());
		return byteArray2HexString(messageDigest.digest());
	}
	private static String byteArray2HexString(byte[] bytes) {
		StringBuilder stringBuilder = new StringBuilder();
		for(byte b : bytes) {
			stringBuilder.append(HEX_DIGITS[(b & 0xf0) >> 4]).append(HEX_DIGITS[(b & 0x0f)]);
		}
		return stringBuilder.toString();
	}
    public static void main(String[] args) {
        System.out.println(getMD5String("123456"));
    }
}
