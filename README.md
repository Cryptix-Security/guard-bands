# Guard Bands

**Cryptographic boundaries that make untrusted LLM content inert by default**

## The Problem

Large Language Models process instructions and data through the same input channel, creating a fundamental security vulnerability. When user content (documents, emails, web pages) contains malicious instructions, LLMs may execute them as legitimate commands.

This is the same architectural flaw that plagued early computing systems until out-of-band signaling separated control from data.

## The Solution

**Guard Bands** wrap untrusted content with cryptographically signed boundaries:

```
⟪INERT:START:r:b64(nonce):h:b64(hash)⟫
[Untrusted user content goes here]
⟪INERT:END:mac:b64(mac):kid:keyid⟫
```

**Key Innovation**: The LLM cannot treat content as "safe data" unless it first calls a verification service that validates the cryptographic signatures. Invalid signatures mean the content should be treated as potentially malicious instructions.

## How It Works

1. **Wrapping**: Untrusted content gets wrapped with cryptographically signed markers
2. **Binding**: Signatures are tied to specific context (request ID, model, timestamp)
3. **Verification**: LLM must call verification service before treating content as inert
4. **Policy Enforcement**: Only validated content can be used for tool calls or sensitive operations

## Security Benefits

- **Prevents Forgery**: Attackers cannot create valid markers without signing keys
- **Context Binding**: Signatures prevent replay attacks across conversations  
- **Tamper Detection**: Any content modification invalidates the signature
- **Time Boxing**: Built-in expiration prevents stale attacks

## Implementation Advantages

- **No Model Changes**: Works with existing LLMs (OpenAI, Anthropic, etc.)
- **Incremental Deployment**: Apply selectively to high-risk content
- **Measurable Security**: Clear metrics on prevented injection attempts
- **Performance Conscious**: Crypto operations happen server-side

## Advanced Features

- **API-Level Isolation**: Mutual exclusion between data and instruction modes
- **Progressive Security**: Multiple security levels from basic to maximum
- **Forward Secrecy**: Optional progressive ratcheting for conversation-level protection

## Validation & Testing

**Empirical Validation**: The Guard Bands implementation has been tested against known prompt injection vulnerabilities in earlier Claude models to validate the security mechanism's effectiveness.

### Test Results

Five critical attack vectors tested against Claude models with documented vulnerabilities:

🛡️ **Context Tampering** → ✗ Blocked  
MAC verification failed - content cannot be replayed across conversations

🛡️ **Content Modification** → ✗ Blocked  
Hash mismatch detected - tampering invalidates the signature

🛡️ **Forged Guard Bands** → ✗ Blocked  
Invalid signatures - attackers cannot create valid markers without keys

🛡️ **Unwrapped Malicious Content** → ✗ Blocked  
Missing markers - raw injection attempts rejected at verification

✅ **Normal Operation** → ✓ Passed  
Legitimate wrapped content verified and extracted correctly

**Success Rate**: 100% attack detection and prevention across all test scenarios.

### Why Test Against Older Models?

Testing against earlier model versions with known vulnerabilities provides several advantages:

- **Ethical Disclosure**: Avoids revealing current zero-day vulnerabilities
- **Reproducible Results**: Enables independent verification using documented exploits
- **Conservative Validation**: If Guard Bands protect against known attacks, they provide strong defense against more subtle variants
- **Performance Baseline**: Establishes measurable security improvements

### Test Suite

The implementation includes a comprehensive security test suite demonstrating:
```
✓ Cryptographic signature verification
✓ Context binding enforcement  
✓ Content tampering detection
✓ Forgery prevention
✓ Unwrapped content rejection
```

Run the full test suite: `python3 test_manual.py`

**Interpretation**: Successfully blocking known injection patterns in vulnerable models provides strong evidence that the cryptographic approach will protect against sophisticated attacks in current and future models.

## Status

**Research Phase**: Concept paper completed, implementation in development.

📄 **[Read the Full Paper](./Guard-Bands-Paper.pdf)** - Complete technical specification with threat model, implementation considerations, and business case.

## Quick Start

**📘 [See QUICKSTART.md](./QUICKSTART.md)** for complete build and run instructions.

The POC includes:
- Cryptographic wrapping service
- Verification API
- Claude integration with tool use
- Security test suite
- Interactive demo showing prompt injection prevention

## Research Paper

The complete technical paper includes:
- Detailed threat model analysis
- Implementation architecture
- Deployment strategy
- Business case and operational benefits
- Comparison with existing approaches

## Contributing

This is an open research project. Feedback, suggestions, and contributions are welcome.

## Contact

**Montgomery Toren**  
contact@cryptix.com  
[Cryptix Security](https://github.com/Cryptix-Security)

## License

MIT License - see [LICENSE](LICENSE) for details.
