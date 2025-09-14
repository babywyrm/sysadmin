@Service
@Transactional
@Slf4j
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    @Qualifier("accountService")
    private WebClient accountServiceClient;

    @Autowired
    private AwsCredentialsService awsCredentialsService;

    // Method with zero trust validation
    @PreAuthorize("@zeroTrustValidator.canAccessUser(authentication, #userId)")
    public UserDto findById(String userId) {
        log.info("Finding user: {} with auth context", userId);
        
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(userId));
            
        return UserDto.fromEntity(user);
    }

    // Cross-service call with mTLS
    public TransferResponse initiateTransfer(String userId, TransferRequest request) {
        // First validate local user
        UserDto user = findById(userId);
        
        // Make authenticated call to account service
        try {
            AccountBalanceResponse balance = accountServiceClient
                .get()
                .uri("/api/v1/accounts/{accountId}/balance", request.getFromAccount())
                .header("X-Request-Context", createRequestContext())
                .retrieve()
                .bodyToMono(AccountBalanceResponse.class)
                .block();

            if (balance.getAvailableBalance().compareTo(request.getAmount()) < 0) {
                throw new InsufficientFundsException();
            }

            // Process transfer
            TransferResponse response = accountServiceClient
                .post()
                .uri("/api/v1/accounts/transfer")
                .header("X-Request-Context", createRequestContext())
                .body(Mono.just(request), TransferRequest.class)
                .retrieve()
                .bodyToMono(TransferResponse.class)
                .block();

            log.info("Transfer completed - User: {}, Amount: {}, Reference: {}", 
                    userId, request.getAmount(), response.getTransferReference());

            return response;

        } catch (Exception e) {
            log.error("Transfer failed - User: {}, Error: {}", userId, e.getMessage());
            throw new TransferException("Transfer failed", e);
        }
    }

    private String createRequestContext() {
        // Create request context with current authentication
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        RequestContext context = RequestContext.builder()
            .spiffeId(auth.getName())
            .timestamp(Instant.now())
            .requestId(UUID.randomUUID().toString())
            .build();
            
        return Base64.getEncoder().encodeToString(
            context.toJson().getBytes(StandardCharsets.UTF_8)
        );
    }
}
