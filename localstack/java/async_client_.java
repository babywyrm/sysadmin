package your.package.name;

import java.util.Objects;
import java.util.function.Supplier;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.client.builder.ExecutorFactory;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBAsync;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBAsyncClientBuilder;
import com.amazonaws.services.sqs.AmazonSQSAsync;
import com.amazonaws.services.sqs.AmazonSQSAsyncClientBuilder;

import cloud.localstack.TestUtils;
import cloud.localstack.docker.LocalstackDocker;

/**
 * Utility class for creating AWS async client instances configured for
 * LocalStack testing.
 *
 * <p>This class provides factory methods to create pre-configured AWS service
 * clients that connect to LocalStack endpoints with appropriate credentials.
 *
 * <p>Example usage:
 * <pre>
 * // Basic DynamoDB client
 * AmazonDynamoDBAsync dynamoClient =
 *     TestAsyncUtils.getClientDynamoDBAsync();
 *
 * // SQS client with custom executor
 * ExecutorFactory factory = () -> Executors.newFixedThreadPool(10);
 * AmazonSQSAsync sqsClient =
 *     TestAsyncUtils.getClientSQSAsync(factory);
 * </pre>
 */
public class TestAsyncUtils extends TestUtils {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private TestAsyncUtils() {
        throw new UnsupportedOperationException(
            "Utility class cannot be instantiated"
        );
    }

    // ========================================================================
    // DynamoDB Async Client Factory Methods
    // ========================================================================

    /**
     * Creates a DynamoDB async client configured for LocalStack.
     *
     * <p>The client is configured with:
     * <ul>
     *   <li>LocalStack DynamoDB endpoint</li>
     *   <li>Test credentials provider</li>
     *   <li>Default executor factory</li>
     * </ul>
     *
     * @return configured DynamoDB async client
     * @throws IllegalStateException if LocalStack is not running
     */
    public static AmazonDynamoDBAsync getClientDynamoDBAsync() {
        return buildAsyncClient(
            AmazonDynamoDBAsyncClientBuilder.standard(),
            LocalstackDocker.INSTANCE::getEndpointDynamoDB
        );
    }

    /**
     * Creates a DynamoDB async client with custom executor factory.
     *
     * @param executorFactory custom executor factory for async operations,
     *                        or null to use default
     * @return configured DynamoDB async client
     * @throws IllegalStateException if LocalStack is not running
     */
    public static AmazonDynamoDBAsync getClientDynamoDBAsync(
        ExecutorFactory executorFactory
    ) {
        return buildAsyncClient(
            AmazonDynamoDBAsyncClientBuilder.standard(),
            LocalstackDocker.INSTANCE::getEndpointDynamoDB,
            executorFactory
        );
    }

    // ========================================================================
    // SQS Async Client Factory Methods
    // ========================================================================

    /**
     * Creates an SQS async client configured for LocalStack.
     *
     * <p>The client is configured with:
     * <ul>
     *   <li>LocalStack SQS endpoint</li>
     *   <li>Test credentials provider</li>
     *   <li>Default executor factory</li>
     * </ul>
     *
     * @return configured SQS async client
     * @throws IllegalStateException if LocalStack is not running
     */
    public static AmazonSQSAsync getClientSQSAsync() {
        return getClientSQSAsync(null);
    }

    /**
     * Creates an SQS async client with custom executor factory.
     *
     * @param executorFactory custom executor factory for async operations,
     *                        or null to use default
     * @return configured SQS async client
     * @throws IllegalStateException if LocalStack is not running
     */
    public static AmazonSQSAsync getClientSQSAsync(
        ExecutorFactory executorFactory
    ) {
        return buildAsyncClient(
            AmazonSQSAsyncClientBuilder.standard(),
            LocalstackDocker.INSTANCE::getEndpointSQS,
            executorFactory
        );
    }

    // ========================================================================
    // Generic Client Builder Methods
    // ========================================================================

    /**
     * Builds an AWS async client with standard configuration.
     *
     * @param <T>              the client type
     * @param builder          the AWS client builder
     * @param endpointSupplier supplier providing the service endpoint URL
     * @return configured AWS async client
     * @throws NullPointerException if builder or endpointSupplier is null
     * @throws IllegalStateException if endpoint cannot be retrieved
     */
    private static <T> T buildAsyncClient(
        AwsClientBuilder<?, T> builder,
        Supplier<String> endpointSupplier
    ) {
        return buildAsyncClient(builder, endpointSupplier, null);
    }

    /**
     * Builds an AWS async client with custom executor factory.
     *
     * @param <T>              the client type
     * @param builder          the AWS client builder
     * @param endpointSupplier supplier providing the service endpoint URL
     * @param executorFactory  custom executor factory, or null for default
     * @return configured AWS async client
     * @throws NullPointerException if builder or endpointSupplier is null
     * @throws IllegalStateException if endpoint cannot be retrieved
     */
    private static <T> T buildAsyncClient(
        AwsClientBuilder<?, T> builder,
        Supplier<String> endpointSupplier,
        ExecutorFactory executorFactory
    ) {
        Objects.requireNonNull(builder, "Builder cannot be null");
        Objects.requireNonNull(
            endpointSupplier,
            "Endpoint supplier cannot be null"
        );

        // Configure endpoint and credentials
        builder
            .withEndpointConfiguration(
                createEndpointConfiguration(endpointSupplier)
            )
            .withCredentials(getCredentialsProvider());

        // Add custom executor factory if provided
        if (executorFactory != null && builder instanceof
            com.amazonaws.client.builder.ExecutorFactory.Builder) {
            ((com.amazonaws.client.builder.ExecutorFactory.Builder<?>) builder)
                .withExecutorFactory(executorFactory);
        }

        return builder.build();
    }

    /**
     * Creates endpoint configuration from a supplier.
     *
     * @param endpointSupplier supplier providing the endpoint URL
     * @return endpoint configuration object
     * @throws IllegalStateException if endpoint cannot be retrieved
     */
    private static AwsClientBuilder.EndpointConfiguration
        createEndpointConfiguration(Supplier<String> endpointSupplier) {
        try {
            String endpoint = endpointSupplier.get();
            if (endpoint == null || endpoint.trim().isEmpty()) {
                throw new IllegalStateException(
                    "LocalStack endpoint is not available. " +
                    "Ensure LocalStack is running."
                );
            }
            return getEndpointConfiguration(endpoint);
        } catch (Exception e) {
            throw new IllegalStateException(
                "Failed to retrieve LocalStack endpoint",
                e
            );
        }
    }
}
