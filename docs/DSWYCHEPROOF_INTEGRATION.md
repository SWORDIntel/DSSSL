# DSWycheproof Integration Guide

## Overview

DSWycheproof is a comprehensive cryptographic testing framework that extends Google's Wycheproof with DSMIL (Defense Security Multi-layer Intelligence Linux) integration. It provides military-grade cryptographic assurance for the DSSSL framework.

**Repository**: [SWORDIntel/DSWycheproof](https://github.com/SWORDIntel/DSWycheproof)

### Key Capabilities

- **Device 15 (CRYPTO)**: Core cryptographic testing with PQC support
- **Device 47 (AI)**: Advanced failure analysis and pattern detection
- **Device 46 (QUANTUM)**: Quantum-assisted edge-case discovery
- **Phase D**: Post-Quantum Cryptography extensions
- **Phase E**: MLOps gating and deployment validation

### Supported Cryptographic Primitives

#### Classical Cryptography
- AES-GCM, AES-CCM, AES-EAX
- ECDSA (P-256, P-384, P-521)
- RSA (2048, 3072, 4096)
- ChaCha20-Poly1305
- HMAC (SHA256, SHA384, SHA512)

#### Post-Quantum Cryptography
- ML-KEM-512/768/1024 (Key Encapsulation)
- ML-DSA-44/65/87 (Digital Signatures)

## Installation

### Prerequisites

```bash
# Python version
Python >= 3.9

# For quantum features (optional)
Qiskit >= 1.0.0

# For PQC extensions (optional)
liboqs-python >= 0.10.0
```

### Setup DSWycheproof Submodule

The DSWycheproof submodule is already integrated into DSSSL:

```bash
# Initialize submodule (if not already done)
git submodule update --init --recursive wycheproof

# Update to latest version
git submodule update --remote wycheproof
```

### Install DSWycheproof Package

```bash
# Install from submodule
cd wycheproof
pip install -e .

# Or with all features
pip install -e ".[dev,pqc]"
```

## Usage

### Using DSWycheproof Integration Module

The `dswycheproof_integration.py` module provides a high-level Python API:

```python
from providers.dswycheproof_integration import (
    DSWycheproofIntegration,
    is_dswycheproof_available
)

# Check availability
available, message = is_dswycheproof_available()
if available:
    print(f"Status: {message}")

# Create integration instance
integration = DSWycheproofIntegration()

# List available algorithms
algorithms = integration.list_available_algorithms()
print(f"Available algorithms: {algorithms}")

# Load test vectors
vectors = integration.load_test_vectors('ML-DSA-44')
print(f"Loaded {len(vectors)} test vectors")
```

### Running Test Campaigns

#### Basic Campaign

```bash
cd wycheproof

# Generate example campaign
dsmil-wycheproof generate-example-campaign campaign.yaml

# Run campaign
dsmil-wycheproof run-campaign campaign.yaml \
  --wycheproof-root ./testvectors_v1 \
  --output-dir results
```

#### Analyzing Test Results

```bash
# Analyze failures with Device 47 (AI)
dsmil-wycheproof analyze-results results/*_results.jsonl \
  --output analysis.json

# Generate new test vectors from analysis
dsmil-wycheproof generate-vectors analysis.json \
  --output ai_vectors.json \
  --count 5
```

### ML-DSA Test Vector Parsing

#### Enhanced Parser with DSWycheproof Features

```bash
# Parse ML-DSA-44 sign tests
python3 test/dswycheproof_test_parser.py \
  -alg ML-DSA-44 \
  -type sign \
  wycheproof/testvectors_v1/mldsa_44_sign_seed_test.json

# Generate OpenSSL test data
python3 test/dswycheproof_test_parser.py \
  -alg ML-DSA-44 \
  -type sign \
  wycheproof/testvectors_v1/mldsa_44_sign_seed_test.json \
  > test/recipes/30-test_evp_data/evppkey_ml_dsa_44_wycheproof_sign.txt

# Parse with verbose output
python3 test/dswycheproof_test_parser.py \
  -alg ML-DSA-65 \
  -type both \
  --verbose \
  wycheproof/testvectors_v1/mldsa_65_*.json
```

#### Python API for Parsing

```python
from test.dswycheproof_test_parser import MLDSATestVectorParser

parser = MLDSATestVectorParser(use_dsmil=True)

# Load test vectors
test_data = parser.load_test_vectors('path/to/mldsa_44_sign_seed_test.json')

# Parse to OpenSSL format
output = parser.parse('ML-DSA-44', 'sign', test_data)
print(output)
```

## Integration Points

### 1. Device 15 (CRYPTO) - Core Testing

Located in: `wycheproof/src/dsmil_wycheproof/device15/`

**Components**:
- `campaign_runner.py`: Execute test campaigns
- `vector_loader.py`: Load and parse test vectors
- `result_formatter.py`: Format test results
- `schema_validator.py`: Validate against JSON schemas

**Usage Example**:

```python
from dsmil_wycheproof.device15.campaign_runner import CampaignRunner
from dsmil_wycheproof.device15.vector_loader import VectorLoader

loader = VectorLoader(wycheproof_root='wycheproof')
algorithms = loader.list_algorithms()

runner = CampaignRunner()
campaign_config = {
    'algorithms': ['ECDSA', 'ML-DSA-44'],
    'test_count': 100
}
results = runner.run(campaign_config)
```

### 2. Device 47 (AI) - Failure Analysis

Located in: `wycheproof/src/dsmil_wycheproof/device47/`

**Components**:
- `failure_analyzer.py`: Analyze test failures
- `pattern_detector.py`: Detect failure patterns
- `vector_generator.py`: Generate test vectors from patterns

**Usage Example**:

```python
from dsmil_wycheproof.device47.failure_analyzer import FailureAnalyzer

analyzer = FailureAnalyzer()
failure_report = analyzer.analyze(test_results)
patterns = failure_report.get_patterns()
```

### 3. Device 46 (QUANTUM) - Edge-Case Discovery

Located in: `wycheproof/src/dsmil_wycheproof/device46/`

**Capabilities**:
- Quantum-assisted QAOA search
- Boundary value discovery
- Edge-case identification

**Note**: Requires Qiskit installation for quantum features.

### 4. Layer 8 - PQC Integration

Located in: `wycheproof/src/dsmil_wycheproof/layer8/`

**Features**:
- ML-KEM validation
- ML-DSA validation
- Hybrid crypto schemes

### 5. Layer 9 - MLOps Gating

Located in: `wycheproof/src/dsmil_wycheproof/layer9/`

**Features**:
- Deployment gating criteria
- Executive dashboards
- Compliance reporting

## File Structure

```
DSSSL/
├── wycheproof/                          # DSWycheproof submodule
│   ├── src/dsmil_wycheproof/
│   │   ├── device15/                   # CRYPTO testing
│   │   ├── device46/                   # QUANTUM discovery
│   │   ├── device47/                   # AI analysis
│   │   ├── layer8/                     # PQC extensions
│   │   ├── layer9/                     # MLOps gating
│   │   ├── cli/                        # Command-line tools
│   │   └── common/                     # Shared utilities
│   ├── testvectors_v1/                 # Test vector files
│   ├── schemas/                        # JSON schemas
│   ├── setup.py
│   └── README.md
│
├── providers/
│   └── dswycheproof_integration.py      # Integration module
│
└── test/
    ├── mldsa_wycheproof_parse.py        # Original parser
    ├── dswycheproof_test_parser.py      # Enhanced parser
    └── recipes/30-test_evp_data/        # OpenSSL test data
```

## Python API Reference

### DSWycheproofIntegration Class

```python
class DSWycheproofIntegration:
    """Main integration class for DSWycheproof cryptographic testing."""

    def __init__(self, wycheproof_root: Optional[str] = None)
        """Initialize DSWycheproof integration."""

    def list_available_algorithms(self) -> List[str]
        """List all cryptographic algorithms with test vectors."""

    def load_test_vectors(self, algorithm: str) -> Dict[str, Any]
        """Load test vectors for a specific algorithm."""

    def run_test_campaign(self, campaign_config: Dict[str, Any],
                         output_dir: Optional[str] = None) -> Dict[str, Any]
        """Run a cryptographic test campaign."""

    def get_testvector_path(self, algorithm: str) -> Optional[Path]
        """Get file path for a specific algorithm's test vectors."""
```

### MLDSATestVectorConverter Class

```python
class MLDSATestVectorConverter:
    """Utility for converting ML-DSA Wycheproof vectors to OpenSSL format."""

    @staticmethod
    def convert_test_vector(json_data: Dict[str, Any], algorithm: str,
                           test_type: str = 'sign') -> str
        """Convert Wycheproof ML-DSA test vectors to OpenSSL format."""
```

### Utility Functions

```python
def is_dswycheproof_available() -> Tuple[bool, str]
    """Check if DSWycheproof is properly installed."""

def get_wycheproof_testvector_files(wycheproof_root: Optional[str] = None) -> List[Path]
    """Get list of all available test vector files."""
```

## Common Tasks

### 1. Generate ML-DSA Test Data for OpenSSL

```bash
#!/bin/bash
# Generate all ML-DSA test data for OpenSSL testing

for ALG in ML-DSA-44 ML-DSA-65 ML-DSA-87; do
    # Sign tests
    python3 test/dswycheproof_test_parser.py \
        -alg $ALG -type sign \
        wycheproof/testvectors_v1/mldsa_*_sign_*_test.json \
        > test/recipes/30-test_evp_data/evppkey_${ALG,,}_wycheproof_sign.txt

    # Verify tests
    python3 test/dswycheproof_test_parser.py \
        -alg $ALG -type verify \
        wycheproof/testvectors_v1/mldsa_*_verify_test.json \
        > test/recipes/30-test_evp_data/evppkey_${ALG,,}_wycheproof_verify.txt
done
```

### 2. Analyze Cryptographic Test Results

```python
from providers.dswycheproof_integration import (
    DSWycheproofIntegration,
    CryptographicAssuranceReport
)

integration = DSWycheproofIntegration()

# Run campaign
campaign_config = {
    'algorithms': ['ECDSA', 'RSA', 'ML-DSA-44'],
    'test_vectors_per_algo': 1000
}

results = integration.run_test_campaign(campaign_config)

# Generate report
report = CryptographicAssuranceReport.generate_summary(results)
print(report)
```

### 3. Extend with Custom Test Vectors

```python
from dsmil_wycheproof.device47.vector_generator import VectorGenerator
from providers.dswycheproof_integration import DSWycheproofIntegration

integration = DSWycheproofIntegration()
analyzer = VectorGenerator()

# Load failure analysis
failures = integration.run_test_campaign({'algorithms': ['ECDSA']})

# Generate vectors targeting edge cases
new_vectors = analyzer.generate(failures, algorithm='ECDSA', count=50)
```

## Troubleshooting

### DSWycheproof Module Not Found

```bash
# Ensure submodule is initialized
git submodule update --init --recursive wycheproof

# Install package in development mode
cd wycheproof
pip install -e .
```

### Missing Test Vector Files

```bash
# Verify testvectors_v1 directory exists
ls wycheproof/testvectors_v1/

# If empty, check git status
cd wycheproof && git status
```

### Python Import Errors

```bash
# Add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/wycheproof/src"

# Or install package
cd wycheproof && pip install -e .
```

## References

- [DSWycheproof Repository](https://github.com/SWORDIntel/DSWycheproof)
- [Google Wycheproof Project](https://github.com/google/wycheproof)
- [C2SP Wycheproof Vectors](https://github.com/C2SP/wycheproof)
- [ML-DSA Specification (FIPS 204)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [ML-KEM Specification (FIPS 203)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

## License

DSWycheproof is licensed under the Apache License 2.0, compatible with DSSSL's licensing.
