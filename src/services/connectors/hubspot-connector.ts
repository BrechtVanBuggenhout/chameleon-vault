import axios from 'axios';
import { IWipeConnector, WipeResult } from './types.js';
import { createLogger } from '../../logging/index.js';

const logger = createLogger('hubspot-connector');

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
        }
      );

      const contacts = searchResponse.data.results;

      if (!contacts || contacts.length === 0) {
        logger.info({ userId, tenantId }, 'No contact found in HubSpot for this user');
        return { success: true, destination: 'hubspot' };
      }

      // 2. Delete all matching contacts
      for (const contact of contacts) {
        await axios.delete(`${this.baseUrl}/${contact.id}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        logger.info({ userId, tenantId, contactId: contact.id }, 'Successfully wiped contact from HubSpot');
      }

      return { success: true, destination: 'hubspot' };
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