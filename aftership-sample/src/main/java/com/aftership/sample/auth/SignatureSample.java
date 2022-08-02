package com.aftership.sample.auth;

import com.aftership.sample.SampleUtil;
import com.aftership.sdk.AfterShip;
import com.aftership.sdk.auth.AuthenticationType;
import com.aftership.sdk.endpoint.impl.EndpointPath;
import com.aftership.sdk.exception.AftershipException;
import com.aftership.sdk.model.tracking.GetTrackingsParams;
import com.aftership.sdk.model.tracking.NewTracking;
import com.aftership.sdk.model.tracking.PagedTrackings;
import com.aftership.sdk.model.tracking.Tracking;

import java.util.HashMap;

public class SignatureSample {
  public static void main(String[] args) {
    // add sign
    String APIKEY = "asak_342fb1e9f2b944e2e6b4522f1640b517";
    String SECRET = "-----BEGIN PRIVATE KEY-----\n" +
      "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJU81GEltRkMHLhG\n" +
      "pyKbmtm36DFgCSLsGfOQjpjRyuR+2DKd3zEk32yQ7Vgphvk0XSlYvZKMBZXPWFkv\n" +
      "OEuia90qIGWjmv0nBqzgXeMbPtqvFLobjdvEUxYofHUjkt9rWxhSdBJr3b60uBzh\n" +
      "PLAL+o8UxBXzFvSOww2DMNLzSonPAgMBAAECgYAfHNpuEm1p9mN6a4hmp6gl4bhv\n" +
      "qsTc2fojFC0WYQ56ipNKIi2o0jYeLSy+J5IzHB6cAxsqlTSI4fxaQ4TqB8eSt7bU\n" +
      "eYICahnumCgktWRCkd9ySv7+6xxWr9KbqLElyld9M4uNOQagiSpn2N/pUTmv1j5g\n" +
      "u+3RYNUyqSCT7eGVEQJBAMYeqtfyMwP6NpQEeSkslKo9owl2gx+eq2n1JvnnBJzH\n" +
      "0Kbvb9RGdowcZSg4c3J4QPZk+Is0hN/EFzVtVqvMOvcCQQDA1kaQtFoDo7EmDmnJ\n" +
      "IdgugqjHKFeSyaF4oo7pS6a6dy70oisnRFx96u+z7Lfw5aVqFSlRDYZmJ8yIkuGe\n" +
      "H1npAkAtNyCMikUkWj2MiHzSbc88DzcfWMHSPJcoZn/Ptu6xjVTMVIb0LmSt02ku\n" +
      "xbtrW5CP6zliI8lTfGBDnEGUkda/AkEApATdqnEsaxINOGBkDAa0eQL7icI/koPb\n" +
      "yt8BjV+iZdG/56YT7GdSAGwXDEPZRJYf9zYemWlWmodZigTc0IC8GQJBALSu7Njd\n" +
      "KWNRCGEyzJ5Et2kKnEc6F6u/+ozJdiqNQg96bMHyGvPi645IM9um30K6Q3nKDIqL\n" +
      "SDWI9Q83D9Rh8S0=\n" +
      "-----END PRIVATE KEY-----";
    AfterShip afterShipSign = new AfterShip(APIKEY, AuthenticationType.RSA, SECRET, SampleUtil.getAftershipOption());
//    createTracking(afterShipSign);
    getTrackings(afterShipSign);
  }

  public static void createTracking(AfterShip afterShip) {
    System.out.println(EndpointPath.CREATE_TRACKING);

    NewTracking newTracking = new NewTracking();
    // slug from listAllCouriers()
    newTracking.setSlug(new String[]{"acommerce"});
    newTracking.setTrackingNumber("1234567890");
    newTracking.setTitle("Title Name");
    newTracking.setSmses(new String[]{"+18555072509", "+18555072501"});
    newTracking.setEmails(new String[]{"email@yourdomain.com", "another_email@yourdomain.com"});
    newTracking.setOrderId("ID 1234");
    newTracking.setOrderIdPath("http://www.aftership.com/order_id=1234");
    newTracking.setCustomFields(
      new HashMap<String, String>(2) {
        {
          put("product_name", "iPhone Case");
          put("product_price", "USD19.99");
        }
      });
    newTracking.setLanguage("en");
    newTracking.setOrderPromisedDeliveryDate("2019-05-20");
    newTracking.setDeliveryType("pickup_at_store");
    newTracking.setPickupLocation("Flagship Store");
    newTracking.setPickupNote(
      "Reach out to our staffs when you arrive our stores for shipment pickup");

    try {
      Tracking tracking = afterShip.getTrackingEndpoint().createTracking(newTracking);
      System.out.println(tracking);
    } catch (AftershipException e) {
      System.out.println(e.getMessage());
    }
  }

  public static void getTrackings(AfterShip afterShip) {
    System.out.println(EndpointPath.GET_TRACKING);

    GetTrackingsParams optionalParams = new GetTrackingsParams();
    optionalParams.setFields("title,order_id");
    optionalParams.setLang("china-post");
    optionalParams.setLimit(10);

    try {
      PagedTrackings pagedTrackings = afterShip.getTrackingEndpoint().getTrackings(optionalParams);
      System.out.println(pagedTrackings);
    } catch (AftershipException e) {
      System.out.println(e.getMessage());
    }
  }
}
