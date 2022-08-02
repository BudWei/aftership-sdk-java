package com.aftership.sdk.auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class AMHmacSigner {
  private final String secret;

  public AMHmacSigner(String secret) {
    this.secret = secret;
  }

  public static void main(String[] args) {
    AMHmacSigner signer = new AMHmacSigner("token_ugG_Kz_Yin-lvKCiUCJjIegbbLfQNAh7RYPVScFXHTAnfyl-6R.0tRgcW!");
    String method = "POST";
    String contentType = "application/json";
    ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC);
    String date = DateTimeFormatter.RFC_1123_DATE_TIME.format(zdt);
    String canonicalizedResource = "";
    try {
      URL url = new URL("http://localhost/commerce/v1/products");
      canonicalizedResource = signer.getCanonicalizedResource(url);
    } catch (MalformedURLException | UnsupportedEncodingException e) {
      e.printStackTrace();
    }
    Map<String, String> amHeaders = new HashMap<>();
    amHeaders.put("am-app-id", "c25b1e6fee2348b3a8bd21599b6ac2de");
    amHeaders.put("am-store-id", "test");
    String canonicalizedAmHeaders = signer.getCanonicalizedAmHeaders(amHeaders);
    String body = "{\n  \"source_id\": \"00093d19495447a2a08dsfe44d75218a\",\n  \"title\": \"girls hoodies baby girl clothes\",\n  \"slug\": \"girls-hoodies-baby-girl-clothes\",\n  \"categories\": [\n    \"shoes\",\n    \"\"\n  ],\n  \"tags\": [\n    \"baby\"\n  ],\n  \"image_urls\": [\n    \"https://cdn.shopify.com/s/files/1/1833/4459/products/H70b82b6b95f3441eab7f10c09ed7d9b5S.jpg?v=1593880534\"\n  ],\n  \"url\": \"https://digisource.myshopify.com/products/girls-hoodies-baby-girl-clothes\",\n  \"published\": true,\n  \"description\": \"\",\n  \"variants\": [\n    {\n      \"source_id\": \"00b0a1e329cf4ecc861136ed0ab94fc2\",\n      \"available_quantity\": 20,\n      \"sku\": \"4000144465802-BLACK-DRESSES-2T\",\n      \"title\": \"girls hoodies baby girl clothes\",\n      \"price\": \"31.8\",\n      \"image_urls\": [\n        \"https://cdn.shopify.com/s/files/1/1833/4459/products/Ha30f5cd488314a28b799dca2ff3d2606i.jpg?v=1593793159\"\n      ],\n      \"compare_at_price\": null,\n      \"weight\": {\n        \"unit\": \"kg\",\n        \"value\": 0.35\n      },\n      \"allow_backorder\": true,\n      \"options\": [\n        {\n          \"name\": \"Color\",\n          \"value\": \"BLACK DRESSES\"\n        },\n        {\n          \"name\": \"Kid Size\",\n          \"value\": \"2T\"\n        }\n      ]\n    }\n  ],\n  \"source_created_at\": \"2020-07-03T15:37:30+00:00\",\n  \"source_updated_at\": \"2020-07-04T16:41:50+00:00\"\n}";

    String signString = signer.getSignString(method, body, contentType, date, canonicalizedAmHeaders, canonicalizedResource);
    String signature = signer.getHmacSignature("hello");
    System.out.printf("as-signature-hmac-sha256: %s\n", signature);
  }

  public String getCanonicalizedAmHeaders(Map<String, String> headers) {
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

  public String getCanonicalizedResource(URL url) throws java.io.UnsupportedEncodingException {
    StringBuilder buffer = new StringBuilder();
    buffer.append(url.getPath());
    String query = url.getQuery();
    if (query != null) {
      buffer.append("?");
      buffer.append(URLEncoder.encode(query, String.valueOf(StandardCharsets.UTF_8)));
    }
    return buffer.toString();
  }

  public String getSignString(String method, String body, String contentType, String date, String canonicalizedAmHeaders, String canonicalizedResource) {
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

  public String getHmacSignature(String signString) {
    try {
      Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
      SecretKeySpec secret_key = new SecretKeySpec(this.secret.getBytes(), "HmacSHA256");
      sha256_HMAC.init(secret_key);
      return Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(signString.getBytes()));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static String getMD5Str(String str) {
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
}