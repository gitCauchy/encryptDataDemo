package com.cauchy.encrypt;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

/**
 * @description 非对称加密工具类，采用RSA算法加解密
 * @author Cauchy
 * @date 2019/09/10
 *
 */
public class DissymetricalEncryptUtils {
	
	/**
	 * @description 创建密钥生成器
	 * @param keySize 密钥长度
	 * @return keyPairMap
	 */
	public static Map<String,String>createKeys(int keySize){
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		}catch(NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("No such algorithm");
		}
		// 初始化KeyPairGenerator对象
		keyPairGenerator.initialize(keySize);
		// 生成密匙对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// 得到公钥
		Key publicKey = keyPair.getPublic();
		String publicKeyStr = Base64.encodeBase64URLSafeString(publicKey.getEncoded());
		// 得到私钥
		Key privateKey = keyPair.getPrivate();
		String privateKeyStr = Base64.encodeBase64URLSafeString(privateKey.getEncoded());
		Map<String,String> keyPairMap = new HashMap<String,String>();
		keyPairMap.put("publicKey", publicKeyStr);
		keyPairMap.put("privateKey",privateKeyStr);
		return keyPairMap;
	}
	public static RSAPublicKey getPublicKey(String publicKey)throws NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
		RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
		return key;
	}
	/**
	 * 获取私钥
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
		RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		return key;
	}
	/**
	 * @description 公钥加密
	 * @param data 待加密数据
	 * @param publicKey 公钥
	 */
	public static String publicEncrypt(String data,RSAPublicKey publicKey) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher,Cipher.ENCRYPT_MODE,data.getBytes(CHARSET),publicKey.getModulus().bitLength()));
		}catch(Exception e) {
			throw new RuntimeException("加密字符串遇到异常");
		}
	}
	/**
	 * @description 私钥解密
	 * @param data 待加密数据
	 * @param privateKey 私钥
	 */
	public static String privateDecrypt(String data,RSAPrivateKey privateKey) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return new String(rsaSplitCodec(cipher,Cipher.DECRYPT_MODE,Base64.decodeBase64(data),privateKey.getModulus().bitLength()),CHARSET);
		}catch(Exception e) {
			throw new RuntimeException("解密字符串遇到异常");
		}
	}
	 /**
     * @description 私钥加密
     * @param data
     * @param privateKey
     * @return
     */

    public static String privateEncrypt(String data, RSAPrivateKey privateKey){
        try{
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET), privateKey.getModulus().bitLength()));
        }catch(Exception e){
            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 公钥解密
     * @param data
     * @param publicKey
     * @return
     */

    public static String publicDecrypt(String data, RSAPublicKey publicKey){
        try{
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data), publicKey.getModulus().bitLength()), CHARSET);
        }catch(Exception e){
            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
        }
    }

    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize){
        int maxBlock = 0;
        if(opmode == Cipher.DECRYPT_MODE){
            maxBlock = keySize / 8;
        }else{
            maxBlock = keySize / 8 - 11;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] buff;
        int i = 0;
        try{
            while(datas.length > offSet){
                if(datas.length-offSet > maxBlock){
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                }else{
                    buff = cipher.doFinal(datas, offSet, datas.length-offSet);
                }
                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
        }catch(Exception e){
            throw new RuntimeException("加解密阀值为["+maxBlock+"]的数据时发生异常", e);
        }
        byte[] resultDatas = out.toByteArray();
        IOUtils.closeQuietly(out);
        return resultDatas;
    }
    public static void main (String[] args) throws Exception {
        Map<String, String> keyMap = DissymetricalEncryptUtils.createKeys(1024);
        String  publicKey = keyMap.get("publicKey");
        String  privateKey = keyMap.get("privateKey");
        System.out.println("公钥: \n\r" + publicKey);
        System.out.println("私钥： \n\r" + privateKey);

        System.out.println("公钥加密——私钥解密");
        String str = "HelloWorld";
        System.out.println("\r明文：\r\n" + str);
        System.out.println("\r明文大小：\r\n" + str.getBytes().length);
        String encodedData = DissymetricalEncryptUtils.publicEncrypt(str, DissymetricalEncryptUtils.getPublicKey(publicKey));
        System.out.println("密文：\r\n" + encodedData);
        String decodedData = DissymetricalEncryptUtils.privateDecrypt(encodedData, DissymetricalEncryptUtils.getPrivateKey(privateKey));
        System.out.println("解密后文字: \r\n" + decodedData);


    }
    /**
	 * 设定字符集
	 */
	private static final String CHARSET = "UTF-8";
}
