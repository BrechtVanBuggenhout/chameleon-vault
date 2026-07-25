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
}

export const connectorRegistry = new ConnectorRegistry();