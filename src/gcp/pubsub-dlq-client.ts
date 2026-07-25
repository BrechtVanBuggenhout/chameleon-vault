import { PubSub, Topic } from '@google-cloud/pubsub';
import { createLogger } from '../logging/index.js';

const logger = createLogger('pubsub-dlq-client');

export interface FailedWipeEvent {
  userId: string;
  destination: string;
  error: string;
  timestamp?: string;
}

export class PubSubDLQClient {
  private pubsub: PubSub;
  private topicName: string;
  private topic: Topic;

  constructor(projectId: string, topicName: string) {
    this.pubsub = new PubSub({ projectId });
    this.topicName = topicName;
    this.topic = this.pubsub.topic(topicName);
  }

  /**
   * Publish a failed wipe attempt to the Dead Letter Queue topic.
   * The Pub/Sub subscription will automatically forward this to BigQuery.
   */
  async publishFailedWipe(event: FailedWipeEvent): Promise<string> {
    try {
      const messageId = await this.topic.publish(
        Buffer.from(
          JSON.stringify({
            userId: event.userId,
            destination: event.destination,
            error: event.error,
            timestamp: event.timestamp || new Date().toISOString()
          })
        ),
        {
          userId: event.userId,
          destination: event.destination,
          severity: 'HIGH',
          source: 'janitor-service'
        }
      );

      logger.info(
        { userId: event.userId, destination: event.destination, messageId },
        'Failed wipe published to DLQ'
      );

      return messageId;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(
        { userId: event.userId, destination: event.destination, error: errorMessage },
        'Failed to publish to DLQ'
      );
      throw error;
    }
  }

  /**
   * Verify topic exists and is accessible.
   */
  async verifyTopicExists(): Promise<boolean> {
    try {
      const [exists] = await this.topic.exists();
      return exists;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error({ error: errorMessage }, 'Failed to verify DLQ topic existence');
      return false;
    }
  }
}
