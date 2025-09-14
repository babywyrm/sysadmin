```
src/
├── main/
│   ├── java/
│   │   └── com/
│   │       └── mycompany/
│   │           └── banking/
│   │               ├── UserServiceApplication.java
│   │               ├── config/
│   │               │   ├── ZeroTrustSecurityConfig.java
│   │               │   ├── ServiceClientConfig.java
│   │               │   └── AwsConfig.java
│   │               ├── controller/
│   │               │   ├── UserController.java
│   │               │   └── AccountController.java
│   │               ├── service/
│   │               │   ├── UserService.java
│   │               │   ├── ZeroTrustValidator.java
│   │               │   └── AwsCredentialsService.java
│   │               ├── security/
│   │               │   ├── SpiffeJwtDecoder.java
│   │               │   ├── SessionLifecycleManager.java
│   │               │   └── SpiffeX509ContextHolder.java
│   │               ├── dto/
│   │               │   ├── UserDto.java
│   │               │   ├── TransferRequest.java
│   │               │   ├── TransferResponse.java
│   │               │   └── RequestContext.java
│   │               ├── entity/
│   │               │   └── User.java
│   │               ├── repository/
│   │               │   └── UserRepository.java
│   │               └── exception/
│   │                   ├── UserNotFoundException.java
│   │                   ├── InsufficientFundsException.java
│   │                   └── TransferException.java
│   └── resources/
│       ├── application.yml
│       ├── application-k8s.yml
│       └── application-local.yml
└── test/
    └── java/
        └── com/
            └── mycompany/
                └── banking/
                    ├── integration/
                    │   └── UserControllerIntegrationTest.java
                    └── unit/
                        ├── UserServiceTest.java
                        └── ZeroTrustValidatorTest.java
