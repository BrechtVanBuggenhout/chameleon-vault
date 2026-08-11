import axios from 'axios';
import { IWipeConnector, WipeResult } from './types.js';
import { createLogger } from '../../logging/index.js';

const logger = createLogger('hubspot-connector');

// Without an explicit timeout, axios waits forever on a hung connection --
// worse than an error, since the caller (janitor.ts's retry loop) never
// even sees a failure to retry against. 30s is generous for a REST call
// against HubSpot's API while still failing fast enough that a genuinely
// stuck connection doesn't stall the whole deletion cascade indefinitely.
const REQUEST_TIMEOUT_MS = 30_000;

export class HubSpotConnector implements IWipeConnector {
  readonly name = 'hubspot';
  private apiToken?: string;
  private baseUrl = 'https://api.hubapi.com/crm/v3/objects/contacts';

  constructor(apiToken?: string) {
    this.apiToken = apiToken;
  }

  /**
   * Performs a PII wipe for a user in HubSpot.
   * Uses the Search API to find the contact by the 'chameleon_user_id' custom property.
   */
  async wipe(userId: string, tenantId: string): Promise<WipeResult> {
    const token = this.apiToken || process.env.HUBSPOT_API_KEY;
    if (!token) {
      logger.error('HUBSPOT_API_KEY not configured');
      return { success: false, destination: 'hubspot', error: 'Configuration error' };
    }

    try {
      // 1. Search for the contact in HubSpot
      const searchResponse = await axios.post(
        `${this.baseUrl}/search`,
        {
          filterGroups: [
            {
              filters: [
                {
                  propertyName: 'chameleon_user_id',
                  operator: 'EQ',
                  value: userId,
                },
              ],
            },
          ],
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          timeout: REQUEST_TIMEOUT_MS,
        }
      );

      const contacts = searchResponse.data.results;

      if (!contacts || contacts.length === 0) {
        logger.info({ userId, tenantId }, 'No contact found in HubSpot for this user');
        return { success: true, destination: 'hubspot', recordsFound: 0 };
      }

      // 2. Delete all matching contacts
      for (const contact of contacts) {
        await axios.delete(`${this.baseUrl}/${contact.id}`, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: REQUEST_TIMEOUT_MS,
        });
        logger.info({ userId, tenantId, contactId: contact.id }, 'Successfully wiped contact from HubSpot');
      }

      return { success: true, destination: 'hubspot', recordsFound: contacts.length };
    } catch (error: any) {
      const status = error.response?.status;
      const isRetryable = status === 429 || (status >= 500 && status < 600);

      logger.error({ err: error.message, userId, status, isRetryable }, 'HubSpot wipe failed');

      return {
        success: false,
        destination: 'hubspot',
        error: error.message,
        retryable: isRetryable,
      };
    }
  }
}