#!/bin/bash

# Environment variables for configuration
# RUN_MODE: "start" (default) or "verify" - determines which npm script to run
#   - "start": runs npm run start (deploy/run examples)
#   - "verify": runs npm run verify (verify historical data)
#
# Examples:
#   RUN_MODE=start ./scripts/run-examples.sh
#   RUN_MODE=verify ./scripts/run-examples.sh
RUN_MODE=${RUN_MODE:-"start"}
ABIS_DOWNLOADED=${ABIS_DOWNLOADED:-"true"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[EXAMPLE]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
print_status "Checking prerequisites..."

if ! command_exists npm; then
    print_error "npm is not installed"
    exit 1
fi

if ! command_exists node; then
    print_error "node is not installed"
    exit 1
fi

print_status "Prerequisites check passed"

# Function to run a single example
run_example() {
    local example_dir="$1"
    local example_name=$(basename "$example_dir")
    local exit_code=0
    
    print_header "Running example: $example_name"
    echo "=========================================="
    
    cd "$example_dir"
    
    # Copy contracts to example directory
    print_status "Setting up contracts for $example_name..."
    mkdir -p src/abis
    if ! cp -r ../../contracts/abis/* src/abis/ 2>/dev/null; then
        print_error "No contracts found to copy for $example_name"
        cd ../..
        return 1
    fi

    mkdir -p src/zeto-abis
    if ! cp -r ../../contracts/zeto-abis/* src/zeto-abis/ 2>/dev/null; then
        print_error "No zeto contracts found to copy for $example_name"
        cd ../..
        return 1
    fi

    # Install dependencies
    print_status "Installing dependencies for $example_name..."

    if [ "$USE_PUBLISHED_SDK" = "false" ]; then
        print_status "Switching to local SDK for $example_name..."
        npm uninstall @lfdecentralizedtrust-labs/paladin-sdk 2>/dev/null || true
        npm install file:../../sdk/typescript
    fi
    
    if ! npm install; then
        print_error "Failed to install dependencies for $example_name"
        cd ../..
        return 1
    fi

    if [ "$ABIS_DOWNLOADED" = "false" ]; then
        rm -rf src/abis/* 2>/dev/null || true # remove all files in the abis directory
        rm -rf src/zeto-abis/* 2>/dev/null || true # remove all files in the zeto-abis directory

        print_status "Running 'npm run abi' for $example_name..."
        npm run abi
    fi
    
    mkdir -p logs
    # Run the example
    print_status "Running $example_name with 'npm run $RUN_MODE'..."
    if ! npm run $RUN_MODE 2>&1 | tee "logs/$example_name.log"; then
        print_error "Example $example_name failed to run"
        exit_code=1
    else
        print_status "Completed example: $example_name"
    fi
    
    echo ""
    cd ../..
    return $exit_code
}

# Main execution
main() {
    print_status "Starting Paladin examples execution..."

    # Check if we're in the right directory
    if [ ! -d "example" ]; then
        print_error "example directory not found. Please run this script from the paladin root directory."
        exit 1
    fi
    
    # List all available examples
    print_status "Available examples:"
    for dir in example/*/; do
        if [ -f "$dir/package.json" ] && [ "$(basename "$dir")" != "common" ]; then
            echo "- $(basename "$dir")"
        fi
    done
    echo ""
    
    # Get list of all example directories (excluding common)
    examples=$(find example -maxdepth 1 -type d -name "*" | grep -v "example$" | grep -v "example/common" | sort)
    
    print_status "Running examples in order:"
    echo "$examples"
    echo ""
    
    local failed_examples=()
    local successful_examples=()
    local skipped_examples=()
    
    for example_dir in $examples; do
        example_name=$(basename "$example_dir")

        # Check if the required script exists
        # TODO: remove this temporary check once we implement the verify script for all examples
        if ! npm run | grep -q "$RUN_MODE"; then
            print_warning "Script 'npm run $RUN_MODE' not found for $example_name, skipping..."
            skipped_examples+=("$example_name")
            continue
        fi

        # skip private-stablecoin if USE_PUBLISHED_SDK is true
        # TODO: remove this check after v0.10.0 release 
        if [ "$example_name" == "private-stablecoin" ] && [ "$USE_PUBLISHED_SDK" = "true" ]; then
            print_status "Skipping $example_name (not supported yet)"
            skipped_examples+=("$example_name")
            continue
        fi
        
        # Check if it's a valid example (has package.json)
        if [ -f "$example_dir/package.json" ]; then
            if run_example "$example_dir"; then
                successful_examples+=("$example_name")
            else
                print_error "Example $example_name failed"
                failed_examples+=("$example_name")
            fi
        else
            print_warning "Skipping $example_name (no package.json found)"
        fi
    done
    
    print_status "USE_PUBLISHED_SDK: $USE_PUBLISHED_SDK"

    # Summary
    echo "=========================================="
    print_status "Examples execution summary:"
    echo "=========================================="
    
    if [ ${#successful_examples[@]} -gt 0 ]; then
        print_status "Successful examples (${#successful_examples[@]}):"
        for example in "${successful_examples[@]}"; do
            echo "  ✅ $example"
        done
    fi

    if [ ${#skipped_examples[@]} -gt 0 ]; then
        print_status "Skipped examples (${#skipped_examples[@]}):"
        for example in "${skipped_examples[@]}"; do
            echo " 🚫 $example"
        done
    fi
    
    if [ ${#failed_examples[@]} -gt 0 ]; then
        print_error "Failed examples (${#failed_examples[@]}):"
        for example in "${failed_examples[@]}"; do
            echo "  ❌ $example"
        done
        exit 1
    else
        print_status "All examples completed successfully! 🎉"
    fi
}

# Run main function
main "$@" 