package com.cauchy.test;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import com.sun.org.apache.xml.internal.security.utils.Base64;

/**
 * @description 对称加密工具类，采用3DES算法加解密
 * @author Cauchy
 * @date 2019/09/04
 */
public class SymmetricalEncryptUtils {
	/**
	 * 编码方式
	 */
	private final static String ENCODING = "utf-8";
	/**
	 * @param key 密钥
	 * @param data 原文
	 * @return encryptedData 密文
	 */
	public static String encryptDataWith3DES(String data, String key) throws Exception {
		// DES算法要求一个可信任的随机数源
		SecureRandom secureRandom = new SecureRandom();
		// 从原始数据创建DESKeySpec对象
		DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());
		// 创建一个密钥工厂，然后用它把DESKeySpec转换成一个SecretKey对象
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
		// 创建一个密钥对象
		SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
		// 在ECB模式中使用DES
		Cipher cipher = Cipher.getInstance("DES/ECB/pkcs5padding");
		// 使用密钥初始化Cipher对象
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, secureRandom);
		// 对待加密数据加密
		byte[] encryptData = cipher.doFinal(data.getBytes(ENCODING));
		return Base64.encode(encryptData);
	}
	/**
	 * 
	 * @param encryptedData 密文
	 * @param key 密钥
	 * @return 解密后的数据
	 */
	public static String decryptDataWith3DES(String encryptedData, String key) throws Exception {
		// DES算法要求一个可信任的随机数源
		SecureRandom secureRandom = new SecureRandom();
		// 从原始密钥数据创建一个DESKeySpec对象
		DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());
		// 创建一个密钥工厂，然后用它把DESKeySpec对象转换成为一个SecretKey对象
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
		// 在ECB模式中使用DES
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		// 用密钥初始化Cipher对象
		cipher.init(Cipher.DECRYPT_MODE, secretKey, secureRandom);
		// 正式进行解密操作
		byte[] decryptData = cipher.doFinal(Base64.decode(encryptedData));
		return new String(decryptData, ENCODING);
	}
}
