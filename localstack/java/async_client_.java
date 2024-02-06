import java.util.function.Supplier;

import cloud.localstack.TestUtils;
import cloud.localstack.docker.LocalstackDocker;

public class TestAsyncUtils extends TestUtils {

    public static AmazonDynamoDBAsync getClientDynamoDBAsync() {
        return AmazonDynamoDBAsyncClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointDynamoDB))
                .withCredentials(getCredentialsProvider())
                .build();
    }

    public static AmazonSQSAsync getClientSQSAsync() {
        return getClientSQSAsync(null);
    }

    public static AmazonSQSAsync getClientSQSAsync(final ExecutorFactory executorFactory) {
        return AmazonSQSAsyncClientBuilder.standard()
                .withEndpointConfiguration(getEndpointConfigurationSQS())
                .withExecutorFactory(executorFactory)
                .withCredentials(getCredentialsProvider())
                .build();
    }


    protected static AwsClientBuilder.EndpointConfiguration createEndpointConfiguration(Supplier<String> supplier) {
        return getEndpointConfiguration(supplier.get());
    }
}
