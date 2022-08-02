package com.aftership.sdk.auth;

import com.aftership.sdk.request.HttpMethod;
import jdk.internal.joptsimple.internal.Strings;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import java.util.*;


/**
 * authentication signature
 */
@Data
@AllArgsConstructor
public class CustomerSignature {
  /**
   * Signature key in request header
   */
  private String header;
  /**
   * Encrypted signature
   */
  private String signature;

  public static final String HeaderASSignatureHMAC = "as-signature-hmac-sha256";
  public static final String HeaderASSignatureRSA = "as-signature-rsa-sha256";

  /**
   * @param authenticationType types of authentications
   * @param secret             the required API secret from the API key generation page.
   * @param headers            request headers
   * @param urlStr             request url
   * @param method             method of http request
   * @param body               request data of body
   * @param contentType        Content type string.If the request body is empty, set content_type to an empty string.
   * @param date               UTC time in RFC 1123 format.Kindly note that the calculated signature is only valid for 3 minutes before or after the datetime indicated in this key.
   * @return Signature
   */
  public static CustomerSignature getSignature(AuthenticationType authenticationType, String secret, Map<String, String> headers, String urlStr, String method, String body, String contentType, String date) {
    if (HttpMethod.POST.getName().equals(method) || HttpMethod.PATCH.getName().equals(method)) {
      contentType = "application/json; charset=utf-8";
    }

    String signString;
    try {
      URL url = new URL(urlStr);
      System.out.println(url);
      signString = getSignString(method, body, contentType, date, getCanonicalizedAmHeaders(headers), getCanonicalizedResource(url));
      System.out.println("signString start");
      System.out.println(signString);
      System.out.println("signString end");
    } catch (MalformedURLException | UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }

    switch (authenticationType) {
      case RSA:
        return new CustomerSignature(HeaderASSignatureRSA, getRSASignature(signString, secret));
      case AES:
        return new CustomerSignature(HeaderASSignatureHMAC, getHMACSignature(signString, secret));
    }
    return null;
  }

  private static String getSignString(String method, String body, String contentType, String date, String canonicalizedAmHeaders, String canonicalizedResource) {
    StringBuilder buffer = new StringBuilder();
    buffer.append(method);
    buffer.append("\n");
    if (body == null) {
      body = "";
    }
    if (!body.equals("")) {
      body = getMD5Str(body).toUpperCase();
    } else {
      contentType = "";
    }
    buffer.append(body).append("\n");
    buffer.append(contentType).append("\n");
    buffer.append(date).append("\n");
    buffer.append(canonicalizedAmHeaders).append("\n");
    buffer.append(canonicalizedResource);
    return buffer.toString();
  }

  private static String getCanonicalizedAmHeaders(Map<String, String> headers) {
    List<String> sortedHeaders = new ArrayList<>(headers.keySet());
    StringBuilder buffer = new StringBuilder();
    sortedHeaders.sort(String.CASE_INSENSITIVE_ORDER);
    for (String key : sortedHeaders) {
      String newKey = key.toLowerCase();
      // only support header with as- prefix
      if (!newKey.startsWith("as-")) {
        continue;
      }
      String value = headers.get(key);
      buffer.append(newKey);
      buffer.append(":");
      if (value != null) {
        buffer.append(value);
      }
      buffer.append("\n");
    }
    return buffer.toString().trim();
  }

  private static String getCanonicalizedResource(URL url) throws java.io.UnsupportedEncodingException {
    StringBuilder buffer = new StringBuilder();
    buffer.append(url.getPath());
    String query = url.getQuery();
    if (query == null) {
      return buffer.toString();
    }
    String[] params = query.split("&");
    Arrays.sort(params);
    String queryStr = String.join( "&",params);
    buffer.append("?");
    buffer.append(queryStr);
    return buffer.toString();
  }


  private static String getHMACSignature(String signString, String secret) {
    try {
      Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
      SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
      sha256_HMAC.init(secret_key);
      return Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(signString.getBytes()));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  private static String getRSASignature(String signString, String secret) {
    try {
      java.security.Signature signature = java.security.Signature.getInstance("SHA256WithRSA");
      signature.initSign(getPrivateKey(secret));
      signature.update(signString.getBytes(StandardCharsets.UTF_8));
      return new String(Base64.getEncoder().encode(signature.sign()));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static PrivateKey getPrivateKey(String privateKey) throws Exception {

    // PKCS1 私钥
    java.security.Security.addProvider(
      new org.bouncycastle.jce.provider.BouncyCastleProvider()
    );
    System.out.println("privateKey start");
    System.out.println(privateKey);
    System.out.println("privateKey end");
//    byte[] decodedKey =privateKey.getBytes();
    byte[] decodedKey = Files.readAllBytes(Paths.get("/Users/mg.hong/api-keys/test-ssh/id_rsa"));
    PemReader reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(decodedKey)));
    PemObject privatePem = reader.readPemObject();
    PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privatePem.getContent());
    KeyFactory factory = KeyFactory.getInstance("RSA");
    return factory.generatePrivate(privateSpec);


    // 转 PKCS8 再访问
//    privateKey = privateKey
//      .replaceAll("-----END PRIVATE KEY-----", "")
//      .replaceAll("-----BEGIN PRIVATE KEY-----", "")
//      .replaceAll(System.lineSeparator(), "");
//    KeyFactory factory = KeyFactory.getInstance("RSA");
////    byte[] priKeyDecodes = org.apache.commons.codec.binary.Base64.decodeBase64(privateKey.getBytes(StandardCharsets.UTF_8));
//    byte[] priKeyDecodes = Base64.getDecoder().decode(privateKey.getBytes(StandardCharsets.UTF_8));
//    PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(priKeyDecodes);
//    return factory.generatePrivate(privateSpec);
  }

  private static String getMD5Str(String str) {
    System.out.println("MD5Str ==="+str);
    String result = "";
    try {
      MessageDigest md5 = MessageDigest.getInstance("md5");
      byte[] digest = md5.digest(str.getBytes(StandardCharsets.UTF_8));
      result = new BigInteger(1, digest).toString(16);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return result;
  }


  private static String getRSASignature2(String signString, String secret) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");

      PrivateKey privateKey = readPemPrivateKey(PRIVATE_KEY_FILE);//getPrivateKey
      //Pullingout parameters which makes up Key
      System.out.println("\n------- PULLING OUT PARAMETERS WHICH MAKES KEYPAIR----------\n");
      RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
      System.out.println("PrivKey Modulus : " + rsaPrivKeySpec.getModulus());
      System.out.println("PrivKey Exponent : " + rsaPrivKeySpec.getPrivateExponent());


      //Encrypt Data using Public Key
      byte[] encryptedData = encryptData(signString);

      return new String(encryptedData);

    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  private static final String PRIVATE_KEY_FILE = "/Users/mg.hong/api-keys/test-3/rsa_private_key_pkcs8.pem";

  public static PrivateKey readPemPrivateKey(String filename) throws Exception {
    // 读取文件
    String key = new String(Files.readAllBytes(Paths.get(filename)), Charset.defaultCharset());
    String privateKeyPEM = key
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replaceAll("\n", "")
      .replace("-----END PRIVATE KEY-----", "");
    byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
    PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(encoded);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(pkcs8);
  }

  /**
   * Encrypt Data
   *
   * @param data
   * @throws IOException
   */
  private static byte[] encryptData(String data) throws IOException {
    System.out.println("\n----------------ENCRYPTION STARTED------------");

    System.out.println("Data Before Encryption :" + data);
    byte[] dataToEncrypt = data.getBytes();
    byte[] encryptedData = null;
    try {
//            PublicKey pubKey = getPublicKey(PUBLIC_KEY_FILE);
      PrivateKey privateKey = readPemPrivateKey(PRIVATE_KEY_FILE);

      Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
      cipher.init(Cipher.ENCRYPT_MODE, privateKey);
      encryptedData = cipher.doFinal(dataToEncrypt);
      String encryptedDataStr = Base64.getEncoder().encodeToString(encryptedData);
      System.out.println("Encryted Data: " + encryptedDataStr);

    } catch (Exception e) {
      e.printStackTrace();
    }

    System.out.println("----------------ENCRYPTION COMPLETED------------");
    return encryptedData;
  }
}





