#!/bin/bash

# Environment variables for configuration
# RUN_COMMANDS: comma-separated list of npm scripts to run (default: "start")
#   - "start": runs npm run start (deploy/run tutorials)
#   - "verify": runs npm run verify (verify historical data)
#   - "start,verify": runs both start and verify commands in sequence
#
# Examples:
#   ./scripts/run-tutorials.sh # this will run all tutorials with the latest paladin SDK and solidity contracts
#   BUILD_PALADIN_SDK=true BUILD_PALADIN_ABI=true ./scripts/run-tutorials.sh
#   PALADIN_SDK_VERSION=0.10.0 ./scripts/run-tutorials.sh # use a specific paladin SDK version
#   PALADIN_ABI_VERSION=v0.10.0 ./scripts/run-tutorials.sh # use a specific paladin solidity version
#   ZETO_ABI_VERSION=v0.2.0 ./scripts/run-tutorials.sh # use a specific zeto solidity version
#   RUN_COMMANDS=start ./scripts/run-tutorials.sh
#   RUN_COMMANDS=verify ./scripts/run-tutorials.sh
#   RUN_COMMANDS=start,verify ./scripts/run-tutorials.sh
RUN_COMMANDS=${RUN_COMMANDS:-"start"}
BUILD_PALADIN_SDK=${BUILD_PALADIN_SDK:-"false"} # build the paladin SDK locally
BUILD_PALADIN_ABI=${BUILD_PALADIN_ABI:-"false"} # build the paladin solidity contracts locally

PALADIN_SDK_VERSION=${PALADIN_SDK_VERSION:-""} # download the paladin SDK from npm (default is latest)
PALADIN_ABI_VERSION=${PALADIN_ABI_VERSION:-""} # download the paladin solidity contracts from npm (default is latest)   
ZETO_ABI_VERSION=${ZETO_ABI_VERSION:-"v0.2.0"} # download the zeto solidity contracts from npm (default is v0.2.0)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

EXAMPLES_DIR=examples

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
    echo -e "${BLUE}[TUTORIAL]${NC} $1"
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


# if build locally is set, make sure the tag is not set
if [ "$BUILD_PALADIN_SDK" = "true" ] && [ "$PALADIN_SDK_VERSION" != "" ]; then
    print_error "You cannot set PALADIN_SDK_VERSION when BUILD_PALADIN_SDK is true"
    exit 1
fi
if [ "$BUILD_PALADIN_ABI" = "true" ] && [ "$PALADIN_ABI_VERSION" != "" ]; then  
    print_error "You cannot set PALADIN_ABI_VERSION when BUILD_PALADIN_ABI is true"
    exit 1
fi

# set paladin SDK version to latest if not set
if [ "$PALADIN_SDK_VERSION" = "" ] && [ "$BUILD_PALADIN_SDK" = "false" ]; then
    PALADIN_SDK_VERSION=latest
    # PALADIN_SDK_VERSION=$(npm view @lfdecentralizedtrust-labs/paladin-sdk version)
    print_status "PALADIN_SDK_VERSION not set, using latest version: $PALADIN_SDK_VERSION"
fi

if [ "$PALADIN_ABI_VERSION" = "" ] && [ "$BUILD_PALADIN_ABI" = "false" ]; then
    PALADIN_ABI_VERSION=latest
    print_status "PALADIN_ABI_VERSION not set, using latest version: $PALADIN_ABI_VERSION"
fi

print_status "Prerequisites check passed"

install_prerequisites() {
    # there are three prerequisites:
    # 1. build solidity contracts
    # 2. build paladin sdk
    # 3. build common
    # now, you can chose not to build the solidity or the SDK and use the published ones

    COPY_CONTRACTS_CMD=contracts

    # build paladin solidity contracts
    if [ "$BUILD_PALADIN_ABI" = "true" ]; then
        print_status "Building paladin solidity contracts..."
        cd solidity
        if ! npm install; then
            print_error "Failed to install dependencies for solidity"
            exit 1
        fi
        if ! npm run compile; then
            print_error "Failed to compile solidity contracts"
            exit 1
        fi
        COPY_CONTRACTS_CMD=abi
        cd ..
    fi

    # build paladin SDK
    if [ "$BUILD_PALADIN_SDK" = "true" ]; then
        print_status "Building paladin SDK..."
        cd sdk/typescript
        if ! npm install; then
            print_error "Failed to install dependencies for paladin SDK"
            exit 1
        fi
        if ! npm run $COPY_CONTRACTS_CMD; then
            print_error "Failed to run abi for paladin SDK"
            exit 1
        fi
        if ! npm run build; then
            print_error "Failed to build paladin SDK"
            exit 1
        fi
        cd ../..
    fi

    # build common
    cd $EXAMPLES_DIR/common
    if ! npm install; then
        print_error "Failed to install dependencies for common"
        exit 1
    fi

    if ! npm run $COPY_CONTRACTS_CMD; then
        print_error "Failed to copy contracts for common using `$COPY_CONTRACTS_CMD`"
        exit 1
    fi

    if ! npm run build; then
        print_error "Failed to build common"
        exit 1
    fi
    cd ../..
}

# switch paladin sdk version
switch_paladin_sdk_version() {
    local name="$1"
    if [ "$BUILD_PALADIN_SDK" = "true" ]; then
        print_status "Running $name with local paladin SDK..."
        npm uninstall @lfdecentralizedtrust-labs/paladin-sdk 2>/dev/null || true
        if ! npm install file:../../sdk/typescript; then
            print_error "Failed to install local SDK for $name"
            exit 1
        fi
    fi

    if [ "$PALADIN_SDK_VERSION" != "" ]; then
        print_status "Running $name with paladin SDK version $PALADIN_SDK_VERSION..."
        npm uninstall @lfdecentralizedtrust-labs/paladin-sdk 2>/dev/null || true
        if ! npm install @lfdecentralizedtrust-labs/paladin-sdk@$PALADIN_SDK_VERSION; then
            print_error "Failed to install SDK version $PALADIN_SDK_VERSION for $name"
            exit 1
        fi
    fi
}

# Function to run a single tutorial
run_tutorial() {
    local tutorials_dir="$1"
    local tutorial_name=$(basename "$tutorials_dir")
    local exit_code=0
    
    print_header "Running tutorial: $tutorial_name"
    echo "=========================================="
    
    cd "$tutorials_dir"
    
    # Install dependencies
    print_status "Installing dependencies for $tutorial_name..."

    # switch to the correct paladin sdk version
    switch_paladin_sdk_version "$tutorial_name"

    if ! npm install; then
        print_error "Failed to install dependencies for $tutorial_name"
        cd ../..
        return 1
    fi

    if ! npm run $COPY_CONTRACTS_CMD; then
        print_error "Failed to run 'npm run $COPY_CONTRACTS_CMD' for $tutorial_name"
        cd ../..
        return 1
    fi  
    
    mkdir -p logs
    
    # Split RUN_COMMANDS by comma and run each command
    IFS=',' read -ra COMMANDS <<< "$RUN_COMMANDS"
    
    for command in "${COMMANDS[@]}"; do
        command=$(echo "$command" | xargs) # trim whitespace
        
        # Check if the required script exists
        if ! npm run | grep -E "^\s*$command\s*$" >/dev/null 2>&1; then
            print_warning "Script 'npm run $command' not found for $tutorial_name, skipping..."
            continue
        fi
        
        # Run the tutorial command
        print_status "Running $tutorial_name with 'npm run $command'..."
        if ! npm run $command; then
            print_error "Tutorial $tutorial_name failed to run command '$command'"
            exit_code=1
            break
        else
            print_status "Completed $tutorial_name command: $command"
        fi
    done
    
    echo ""
    cd ../..
    return $exit_code
}

# Main execution
main() {
    print_status "Starting Paladin tutorials execution..."

    # Check if we're in the right directory
    if [ ! -d "$EXAMPLES_DIR" ]; then
        print_error "$EXAMPLES_DIR directory not found. Please run this script from the paladin root directory."
        exit 1
    fi
    
    # List all available tutorials
    print_status "Available tutorials:"
    for dir in $EXAMPLES_DIR/*/; do
        if [ -f "$dir/package.json" ] && [ "$(basename "$dir")" != "common" ]; then
            echo "- $(basename "$dir")"
        fi
    done
    echo ""

    # install prerequisites
    print_status "Installing prerequisites..."
    install_prerequisites
    print_status "Prerequisites installed"
    
    # Get list of all tutorial directories (excluding common)
    tutorials=$(find $EXAMPLES_DIR -maxdepth 1 -type d -name "*" | grep -v "examples$" | grep -v "$EXAMPLES_DIR/common" | sort)
    
    print_status "Running tutorials in order:"
    echo "$tutorials"
    echo ""
    
    local failed_tutorials=()
    local successful_tutorials=()
    local skipped_tutorials=()
    
    for tutorials_dir in $tutorials; do
        tutorial_name=$(basename "$tutorials_dir")

        # skip private-stablecoin if BUILD_PALADIN_SDK is false
        # TODO: remove this check after v0.10.0 release 
        if [ "$tutorial_name" == "private-stablecoin" ] && [ "$BUILD_PALADIN_SDK" = "false" ]; then
            print_status "Skipping tutorial $tutorial_name (not supported yet)"
            skipped_tutorials+=("$tutorial_name")
            continue
        fi
        
        # Check if it's a valid tutorial (has package.json)
        if [ -f "$tutorials_dir/package.json" ]; then
            run_tutorial "$tutorials_dir"
            exit_code=$?
            if [ $exit_code -eq 0 ]; then
                successful_tutorials+=("$tutorial_name")
            elif [ $exit_code -eq 2 ]; then
                skipped_tutorials+=("$tutorial_name")
            else
                print_error "Tutorial $tutorial_name failed"
                failed_tutorials+=("$tutorial_name")
            fi
        else
            print_warning "Skipping tutorial $tutorial_name (no package.json found)"
        fi
    done
    
    print_status "BUILD_PALADIN_SDK: $BUILD_PALADIN_SDK"
    print_status "BUILD_PALADIN_ABI: $BUILD_PALADIN_ABI"
    print_status "PALADIN_SDK_VERSION: $PALADIN_SDK_VERSION"
    print_status "RUN_COMMANDS: $RUN_COMMANDS"

    # Summary
    echo "=========================================="
    print_status "Tutorials execution summary:"
    echo "=========================================="
    
    if [ ${#successful_tutorials[@]} -gt 0 ]; then
        print_status "Successful tutorials (${#successful_tutorials[@]}):"
        for tutorial in "${successful_tutorials[@]}"; do
            echo "  ✅ $tutorial"
        done
    fi

    if [ ${#skipped_tutorials[@]} -gt 0 ]; then
        print_status "Skipped tutorials (${#skipped_tutorials[@]}):"
        for tutorial in "${skipped_tutorials[@]}"; do
            echo " 🚫 $tutorial"
        done
    fi
    
    if [ ${#failed_tutorials[@]} -gt 0 ]; then
        print_error "Failed tutorials (${#failed_tutorials[@]}):"
        for tutorial in "${failed_tutorials[@]}"; do
            echo "  ❌ $tutorial"
        done
        exit 1
    else
        print_status "All tutorials completed successfully! 🎉"
    fi
}

# Run main function
main "$@" 