export function getRequiredEnv(name: string, testDefault?: string): string {
  const value = process.env[name];
  if (value) {
    return value;
  }

  if (process.env.NODE_ENV === 'test' && testDefault !== undefined) {
    return testDefault;
  }

  throw new Error(`Missing required environment variable: ${name}`);
}
