import { IWipeConnector } from './connectors/types.js';
import { HubSpotConnector } from './connectors/hubspot-connector.js';
import { SalesforceConnector } from './connectors/salesforce-connector.js';

export class ConnectorRegistry {
  private connectors: Map<string, IWipeConnector> = new Map();

  constructor() {
    // Pre-register known connectors
    this.register(new HubSpotConnector());
    this.register(new SalesforceConnector());
  }

  register(connector: IWipeConnector): void {
    this.connectors.set(connector.name.toLowerCase(), connector);
  }

  getConnector(name: string): IWipeConnector | undefined {
    return this.connectors.get(name.toLowerCase());
  }

  // The set of destination *types* this system knows how to wipe -- used by
  // certificate claims to state coverage honestly (what we can check) rather
  // than implying it's every system a user's data ever touched.
  getRegisteredConnectorNames(): string[] {
    return Array.from(this.connectors.keys());
  }
}

export const connectorRegistry = new ConnectorRegistry();