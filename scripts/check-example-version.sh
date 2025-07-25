#!/bin/bash

# Script to check if an example should run based on its metadata and current tag
# Usage: ./check-example-version.sh <example-dir> <current-tag>

set -e

EXAMPLE_DIR="$1"
CURRENT_TAG="$2"

if [ -z "$EXAMPLE_DIR" ] || [ -z "$CURRENT_TAG" ]; then
    echo "Usage: $0 <example-dir> <current-tag>"
    exit 1
fi

METADATA_FILE="$EXAMPLE_DIR/metadata.json"

# Check if metadata file exists
if [ ! -f "$METADATA_FILE" ]; then
    echo "ERROR: Metadata file not found: $METADATA_FILE"
    echo "All examples must have a metadata.json file with 'version' field"
    exit 1
fi

# Special case: if current tag is 999.999.999, this is a local build mode
# In this case, we always want to run all examples regardless of version requirements
if [ "$CURRENT_TAG" = "999.999.999" ]; then
    echo "RUN"
    exit 0
fi

# Extract the version range from metadata
VERSION_RANGE=$(jq -r '.version' "$METADATA_FILE")

if [ "$VERSION_RANGE" = "null" ] || [ -z "$VERSION_RANGE" ]; then
    echo "ERROR: Invalid metadata file $METADATA_FILE - missing or invalid 'version' field"
    exit 1
fi

# Function to normalize version (remove leading v if present)
normalize_version() {
    echo "$1" | sed 's/^v//'
}

# Function to compare semantic versions
compare_versions() {
    local version1="$1"
    local version2="$2"
    
    # Convert versions to comparable numbers (e.g., 0.9.0 -> 000900)
    local v1_num=$(echo "$version1" | awk -F. '{printf "%03d%03d%03d", $1, $2, $3}')
    local v2_num=$(echo "$version2" | awk -F. '{printf "%03d%03d%03d", $1, $2, $3}')
    
    if [ "$v1_num" -lt "$v2_num" ]; then
        echo "lt"
    elif [ "$v1_num" -eq "$v2_num" ]; then
        echo "eq"
    else
        echo "gt"
    fi
}

# Function to check if version satisfies range
satisfies_range() {
    local version="$1"
    local range="$2"
    
    # Normalize version
    version=$(normalize_version "$version")
    
    # Handle different range formats
    case "$range" in
        # Exact version: "0.9.0"
        [0-9]*\.[0-9]*\.[0-9]*)
            local comparison=$(compare_versions "$version" "$range")
            [ "$comparison" = "eq" ]
            ;;
        # Caret range: "^0.9.0" (>=0.9.0 and <1.0.0)
        ^[0-9]*\.[0-9]*\.[0-9]*)
            local base_version=$(echo "$range" | sed 's/^\^//')
            local major=$(echo "$base_version" | cut -d. -f1)
            local next_major=$((major + 1))
            local next_version="$next_major.0.0"
            
            local ge_comparison=$(compare_versions "$version" "$base_version")
            local lt_comparison=$(compare_versions "$version" "$next_version")
            
            [ "$ge_comparison" != "lt" ] && [ "$lt_comparison" = "lt" ]
            ;;
        # Tilde range: "~0.9.0" (>=0.9.0 and <0.10.0)
        ~[0-9]*\.[0-9]*\.[0-9]*)
            local base_version=$(echo "$range" | sed 's/^~//')
            local major=$(echo "$base_version" | cut -d. -f1)
            local minor=$(echo "$base_version" | cut -d. -f2)
            local next_minor=$((minor + 1))
            local next_version="$major.$next_minor.0"
            
            local ge_comparison=$(compare_versions "$version" "$base_version")
            local lt_comparison=$(compare_versions "$version" "$next_version")
            
            [ "$ge_comparison" != "lt" ] && [ "$lt_comparison" = "lt" ]
            ;;
        # Greater than or equal: ">=0.9.0"
        \>=[0-9]*\.[0-9]*\.[0-9]*)
            local base_version=$(echo "$range" | sed 's/^>=//')
            local comparison=$(compare_versions "$version" "$base_version")
            [ "$comparison" != "lt" ]
            ;;
        # Less than: "<0.10.0"
        \<[0-9]*\.[0-9]*\.[0-9]*)
            local base_version=$(echo "$range" | sed 's/^<//')
            local comparison=$(compare_versions "$version" "$base_version")
            [ "$comparison" = "lt" ]
            ;;
        # Default: treat as exact version
        *)
            local comparison=$(compare_versions "$version" "$range")
            [ "$comparison" = "eq" ]
            ;;
    esac
}

# Check if current version satisfies the range
if satisfies_range "$CURRENT_TAG" "$VERSION_RANGE"; then
    echo "RUN"
else
    echo "SKIP"
fi 