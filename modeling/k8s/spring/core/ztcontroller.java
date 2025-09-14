@RestController
@RequestMapping("/api/v1/users")
@Validated
@Slf4j
public class UserController {

    @Autowired
    private UserService userService;
    
    @Autowired
    private ZeroTrustValidator zeroTrustValidator;

    // Get user - can only access own data or admin can access any
    @GetMapping("/{userId}")
    @PreAuthorize("@zeroTrustValidator.canAccessUser(authentication, #userId)")
    @PostAuthorize("@zeroTrustValidator.filterUserData(returnObject, authentication)")
    public ResponseEntity<UserDto> getUser(
            @PathVariable String userId,
            Authentication authentication) {
        
        log.info("User access request - SPIFFE: {}, Target User: {}", 
                authentication.getName(), userId);
        
        UserDto user = userService.findById(userId);
        return ResponseEntity.ok(user);
    }

    // Update user - only owner or admin
    @PutMapping("/{userId}")
    @PreAuthorize("@zeroTrustValidator.canModifyUser(authentication, #userId)")
    public ResponseEntity<UserDto> updateUser(
            @PathVariable String userId,
            @Valid @RequestBody UpdateUserRequest request,
            Authentication authentication) {
        
        // Audit log with SPIFFE context
        log.info("User update request - SPIFFE: {}, Target: {}, Changes: {}", 
                authentication.getName(), userId, request.getChangedFields());
        
        UserDto updatedUser = userService.updateUser(userId, request);
        return ResponseEntity.ok(updatedUser);
    }

    // Cross-tenant operation - strict authorization
    @PostMapping("/{userId}/transfer")
    @PreAuthorize("@zeroTrustValidator.canInitiateTransfer(authentication, #userId)")
    public ResponseEntity<TransferResponse> initiateTransfer(
            @PathVariable String userId,
            @Valid @RequestBody TransferRequest request,
            Authentication authentication) {
        
        // Additional runtime validation
        if (!zeroTrustValidator.validateTransferLimits(authentication, request)) {
            throw new SecurityException("Transfer limits exceeded for SPIFFE ID: " 
                    + authentication.getName());
        }
        
        log.info("Transfer initiation - SPIFFE: {}, User: {}, Amount: {}, To: {}", 
                authentication.getName(), userId, request.getAmount(), request.getToAccount());
        
        TransferResponse response = userService.initiateTransfer(userId, request);
        return ResponseEntity.ok(response);
    }
}
