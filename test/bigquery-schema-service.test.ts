import { describe, expect, it } from '@jest/globals';
import { InvalidResourceIdError, parseBigQueryResourceId } from '../src/gcp/bigquery-schema-service.js';

describe('parseBigQueryResourceId', () => {
  it('parses a well-formed bigquery resource ID', () => {
    expect(parseBigQueryResourceId('bigquery:my-project.my_dataset.my_table')).toEqual({
      projectId: 'my-project',
      datasetId: 'my_dataset',
      tableId: 'my_table',
    });
  });

  it.each([
    'not-a-real-id',
    'bigquery:missing-parts',
    'bigquery:only.two',
    'snowflake:proj.dataset.table',
    '',
  ])('rejects "%s" as invalid', (resourceId) => {
    expect(() => parseBigQueryResourceId(resourceId)).toThrow(InvalidResourceIdError);
  });
});
