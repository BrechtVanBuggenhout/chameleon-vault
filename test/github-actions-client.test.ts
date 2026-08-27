import { jest, describe, it, expect, beforeEach } from '@jest/globals';

const mockPost = jest.fn();
await jest.unstable_mockModule('axios', () => ({
  default: { post: mockPost },
}));

const { GithubActionsClient } = await import('../src/gcp/github-actions-client.js');

describe('GithubActionsClient.dispatchJwksSnapshot', () => {
  let client: InstanceType<typeof GithubActionsClient>;

  beforeEach(() => {
    mockPost.mockReset();
    client = new GithubActionsClient({
      token: 'test-token',
      owner: 'BrechtVanBuggenhout',
      repo: 'chameleon-key-vault',
      workflowFile: 'publish-jwks-snapshot.yml',
    });
  });

  it('posts to the correct dispatch URL with the right headers and body', async () => {
    mockPost.mockResolvedValue({ status: 204, data: undefined });

    await client.dispatchJwksSnapshot('projects/p/.../cryptoKeyVersions/3', 'https://key-vault.example.run.app');

    expect(mockPost).toHaveBeenCalledWith(
      'https://api.github.com/repos/BrechtVanBuggenhout/chameleon-key-vault/actions/workflows/publish-jwks-snapshot.yml/dispatches',
      {
        ref: 'main',
        inputs: { new_kid: 'projects/p/.../cryptoKeyVersions/3', base_url: 'https://key-vault.example.run.app' },
      },
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer test-token',
          Accept: 'application/vnd.github+json',
        }),
      })
    );
  });

  it('never throws on a non-2xx response', async () => {
    mockPost.mockResolvedValue({ status: 401, data: { message: 'Bad credentials' } });

    await expect(client.dispatchJwksSnapshot('kid', 'https://x')).resolves.toBeUndefined();
  });

  it('never throws when the underlying request itself throws (network error)', async () => {
    mockPost.mockRejectedValue(new Error('ECONNRESET'));

    await expect(client.dispatchJwksSnapshot('kid', 'https://x')).resolves.toBeUndefined();
  });
});
