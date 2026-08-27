import axios from 'axios';
import { createLogger } from '../logging/index.js';

const logger = createLogger('github-actions-client');

export interface GithubActionsClientConfig {
  token: string;
  owner: string;
  repo: string;
  workflowFile: string;
}

// Dispatches the publish-jwks-snapshot.yml workflow in this repo, which
// independently fetches this service's own live JWKS and publishes a
// timestamped snapshot into the public chameleon-vault repo -- see that
// workflow file's own comments for why it re-fetches rather than trusting a
// payload from here. Deliberately best-effort: this is called after
// rotateSigningKey() has already succeeded, so a GitHub outage, bad token,
// or rate limit here must never be allowed to fail (or even slow down) the
// rotation request itself.
export class GithubActionsClient {
  constructor(private readonly config: GithubActionsClientConfig) {}

  async dispatchJwksSnapshot(newKid: string, baseUrl: string): Promise<void> {
    try {
      const res = await axios.post(
        `https://api.github.com/repos/${this.config.owner}/${this.config.repo}/actions/workflows/${this.config.workflowFile}/dispatches`,
        { ref: 'main', inputs: { new_kid: newKid, base_url: baseUrl } },
        {
          headers: {
            Authorization: `Bearer ${this.config.token}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
          timeout: 10_000,
          validateStatus: () => true,
        }
      );
      if (res.status >= 300) {
        logger.error({ status: res.status, data: res.data }, 'JWKS mirror dispatch failed');
        return;
      }
      logger.info({ newKid }, 'Dispatched JWKS mirror publish workflow');
    } catch (error) {
      logger.error({ error }, 'JWKS mirror dispatch threw -- rotation is unaffected');
    }
  }
}
