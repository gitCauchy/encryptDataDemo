package com.cauchy.test;

import java.util.Random;
/**
 * @date 2019-10-14
 * @author Cauchy
 *
 */
public class GenerateRandomKey {
	/**
	 * @description 生成一个随机的对称加密密钥
	 * @param length
	 * @return
	 */
	public static String getRandomString(int length) {
		String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		Random random = new Random();
		StringBuffer stringBuffer = new StringBuffer();
		for(int i = 0; i < length; i ++) {
			int number = random.nextInt(62);
			stringBuffer.append(str.charAt(number));
		}
		return stringBuffer.toString();
	}
}
