import axios from 'axios';
import { IWipeConnector, WipeResult } from './types.js';
import { createLogger } from '../../logging/index.js';

const logger = createLogger('salesforce-connector');

export class SalesforceConnector implements IWipeConnector {
  readonly name = 'salesforce';
  private readonly baseUrl = process.env.SALESFORCE_INSTANCE_URL || 'https://login.salesforce.com';
  private readonly apiVersion = 'v57.0';

  async wipe(userId: string, tenantId: string): Promise<WipeResult> {
    const apiKey = process.env.SALESFORCE_API_KEY;
    if (!apiKey) {
      logger.error('SALESFORCE_API_KEY not configured');
      return { success: false, destination: 'salesforce', error: 'Configuration error' };
    }

    try {
      // 1. Authenticate with Salesforce OAuth (simplified - assumes token in API key)
      logger.debug({ userId }, 'Authenticating with Salesforce');

      // 2. Query for Contact/Lead by userId custom field
      const userIdField = process.env.SALESFORCE_USER_ID_FIELD || 'Chameleon_User_ID__c';
      const queryUrl = `${this.baseUrl}/services/data/${this.apiVersion}/query`;

      const queryResponse = await axios.get(queryUrl, {
        params: {
          q: `SELECT Id FROM Contact WHERE ${userIdField} = '${userId}' LIMIT 10`
        },
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        }
      });

      const records = queryResponse.data.records || [];

      if (records.length === 0) {
        logger.info({ userId, tenantId }, 'No Salesforce Contact found for userId, nothing to wipe');
        return { success: true, destination: 'salesforce' };
      }

      // 3. Delete found records via REST API
      const deleteUrl = `${this.baseUrl}/services/data/${this.apiVersion}/sobjects/Contact`;

      for (const record of records) {
        logger.info({ userId, tenantId, recordId: record.Id }, 'Deleting Salesforce Contact');

        await axios.delete(`${deleteUrl}/${record.Id}`, {
          headers: {
            Authorization: `Bearer ${apiKey}`
          }
        });
      }

      return { success: true, destination: 'salesforce' };
    } catch (error: any) {
      const status = error.response?.status;
      const data = error.response?.data;
      const isRetryable = status === 429 || (status >= 500 && status < 600);

      if (status === 429) {
        logger.warn({ userId, tenantId, retryAfter: error.response?.headers['retry-after'] }, 'Salesforce rate limited');
        return {
          success: false,
          destination: 'salesforce',
          error: 'Rate limited',
          retryable: true
        };
      }

      // Handle authentication errors (401, 403) - permanent, don't retry
      if (status === 401 || status === 403) {
        logger.error({ userId, status }, 'Salesforce authentication failed');
        return {
          success: false,
          destination: 'salesforce',
          error: 'Authentication failed',
          retryable: false
        };
      }

      // Handle other transient errors (5xx)
      if (status && status >= 500) {
        logger.warn({ userId, status }, 'Salesforce server error (transient)');
        return {
          success: false,
          destination: 'salesforce',
          error: `Server error (${status})`,
          retryable: true
        };
      }

      logger.error({
        error: error.message,
        status,
        data,
        userId,
        tenantId
      }, 'Salesforce wipe failed');

      return {
        success: false,
        destination: 'salesforce',
        error: data?.message || error.message,
        retryable: isRetryable
      };
    }
  }
}
