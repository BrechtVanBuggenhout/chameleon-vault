import snowflake, { type Connection, type ConnectionOptions } from 'snowflake-sdk';

/**
 * Thin promise wrapper around the callback-based snowflake-sdk. Kept minimal —
 * one connection per repository instance, one query at a time (registry/lineage
 * reads are small, infrequent, and run at process startup).
 */
export class SnowflakeClient {
  // Caches the in-flight connect() promise itself, not just its resolved value.
  // Callers like SnowflakePiiRegistryRepository fire queryRegistry()/queryLineage()
  // concurrently via Promise.all — without this, both would see no cached
  // connection yet and each open its own, since neither await has resolved.
  private connectionPromise: Promise<Connection> | undefined;

  constructor(private readonly options: ConnectionOptions) {}

  private connect(): Promise<Connection> {
    if (!this.connectionPromise) {
      this.connectionPromise = new Promise<Connection>((resolve, reject) => {
        const conn = snowflake.createConnection(this.options);
        conn.connect((err) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(conn);
        });
      });
    }
    return this.connectionPromise;
  }

  /**
   * Snowflake uppercases unquoted identifiers, including result column names
   * (`select field_name` comes back keyed `FIELD_NAME`) — unlike BigQuery,
   * which preserves the case as written. Every row's keys are lowercased here
   * so callers can share the same lowercase-keyed row types across adapters,
   * the same fix applied to the chameleon_pii dbt package's pii_report macro.
   */
  private static lowercaseKeys<T>(row: Record<string, unknown>): T {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(row)) {
      out[key.toLowerCase()] = value;
    }
    return out as T;
  }

  async query<T = Record<string, unknown>>(sqlText: string): Promise<T[]> {
    const conn = await this.connect();
    return new Promise<T[]>((resolve, reject) => {
      conn.execute({
        sqlText,
        complete: (err, _stmt, rows) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(((rows ?? []) as Record<string, unknown>[]).map((row) => SnowflakeClient.lowercaseKeys<T>(row)));
        },
      });
    });
  }
}
