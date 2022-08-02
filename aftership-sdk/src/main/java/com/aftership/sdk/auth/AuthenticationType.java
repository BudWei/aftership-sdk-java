package com.aftership.sdk.auth;

/** Types of authentications */
public enum AuthenticationType {
  /** API-KEY authentication type */
  APIKEY("API-KEY"),

  /** RSA authentication type */
  RSA("RSA"),

  /** AES authentication type */
  AES("AES");

  private String type;

  AuthenticationType(String t) {
    this.type = t;
  }

  /**
   * get value of AuthenticationType
   * @return type
   */
  public String getType() {
    return type;
  }
}
