package com.aftership.sdk.endpoint;

import com.aftership.sdk.exception.ApiException;
import com.aftership.sdk.exception.RequestException;
import com.aftership.sdk.exception.SdkException;
import com.aftership.sdk.model.checkpoint.GetCheckpointParam;
import com.aftership.sdk.model.checkpoint.LastCheckpoint;
import com.aftership.sdk.model.tracking.SlugTrackingNumber;

/** Endpoint provides the interface for all checkpoint API calls */
public interface CheckpointEndpoint {

  /**
   * getLastCheckpoint Return the tracking information of the last checkpoint of a single tracking.
   *
   * @param id A unique identifier generated by AfterShip for the tracking
   * @param optionalParam GetCheckpointParam
   * @return DataEntity DataEntity of LastCheckpoint
   * @throws SdkException
   * @throws RequestException
   * @throws ApiException
   */
  LastCheckpoint getLastCheckpoint(String id, GetCheckpointParam optionalParam)
      throws SdkException, RequestException, ApiException;

  /**
   * getLastCheckpoint Return the tracking information of the last checkpoint of a single tracking.
   *
   * @param identifier identifier of a tracking
   * @param optionalParam GetCheckpointParam
   * @return DataEntity DataEntity of LastCheckpoint
   * @throws SdkException
   * @throws RequestException
   * @throws ApiException
   */
  LastCheckpoint getLastCheckpoint(
      SlugTrackingNumber identifier, GetCheckpointParam optionalParam)
      throws SdkException, RequestException, ApiException;
}
