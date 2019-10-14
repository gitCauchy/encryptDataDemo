package com.cauchy.encrypt;

import java.util.Map;

public class FeatureExhibition {
	public static void main(String[] args) throws Exception{
		// 待加密数据
		String dataForTest = "{\"customerid\":\"123456\",\"cardtype\":\"1\",\"deviceid\":\"12345678910\"}";
		// 先生成一个随机堆成加密密钥
		String key = GenerateRandomKey.getRandomString(8);
		// 加密原始报文
		String encryptedData = SymmetricalEncryptUtils.encryptDataWith3DES(dataForTest, key);
		// 对随机生成密钥进行公钥加密
		Map<String, String> keyMap = DissymetricalEncryptUtils.createKeys(1024);
        String  publicKey = keyMap.get("publicKey");
        String  privateKey = keyMap.get("privateKey");
        // 使用公钥对对称密钥加密
        String encryptedKey = DissymetricalEncryptUtils.publicEncrypt(key, DissymetricalEncryptUtils.getPublicKey(publicKey));
        // 获取MD5散列用于后续进行反篡改校验
        String md5Str1 = HashUtils.getMD5String(dataForTest);
        // ================================================解密过程========================================
        // 使用私钥对公钥加密的对称密钥进行解密处理
        String decryptedKey = DissymetricalEncryptUtils.privateDecrypt(encryptedKey, DissymetricalEncryptUtils.getPrivateKey(privateKey));
        // 使用非对称算法解密出来的对称密钥对加密数据解密
        String decryptedData = SymmetricalEncryptUtils.decryptDataWith3DES(encryptedData, decryptedKey);
        // 对解密的数据获取MD5散列
        String md5Str2 = HashUtils.getMD5String(decryptedData);
        if(md5Str1.equals(md5Str2)) {
        	System.out.println("======================反篡改校验成功================");
        	System.out.println("原始数据：" + decryptedData);
        }else {
        	System.out.println("======================反篡改校验失败================");
        }
	}

}
