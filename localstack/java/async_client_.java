package your.package.name;

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

public class TestAsyncUtils extends TestUtils {

    public static AmazonDynamoDBAsync getClientDynamoDBAsync() {
        return buildAsyncClient(
            AmazonDynamoDBAsyncClientBuilder.standard(),
            LocalstackDocker.INSTANCE::getEndpointDynamoDB
        );
    }

    public static AmazonSQSAsync getClientSQSAsync() {
        return getClientSQSAsync(null);
    }

    public static AmazonSQSAsync getClientSQSAsync(
        ExecutorFactory executorFactory
    ) {
        AmazonSQSAsyncClientBuilder builder = AmazonSQSAsyncClientBuilder
            .standard()
            .withEndpointConfiguration(getEndpointConfigurationSQS())
            .withCredentials(getCredentialsProvider());

        if (executorFactory != null) {
            builder.withExecutorFactory(executorFactory);
        }

        return builder.build();
    }

    private static <T> T buildAsyncClient(
        AwsClientBuilder<?, T> builder,
        Supplier<String> endpointSupplier
    ) {
        return builder
            .withEndpointConfiguration(
                getEndpointConfiguration(endpointSupplier.get())
            )
            .withCredentials(getCredentialsProvider())
            .build();
    }
}
