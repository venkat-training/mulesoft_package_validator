#!/bin/bash
# Shell script to scan all MuleSoft projects in a directory using the orphan checker

# Default values
REPORT_DIR="./reports"
PYTHON_PATH=""
PROJECTS_DIR=""
SINGLE_PROJECT=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to show help
show_help() {
    cat << EOF
MuleSoft Project Scanner - Shell Script

USAGE:
    $0 -d <projects_directory> [-r <report_directory>] [-p <python_path>] [-h]
    $0 -s <single_project> [-r <report_directory>] [-p <python_path>] [-h]

OPTIONS:
    -d, --projects-dir     Base directory containing MuleSoft project repositories (for batch scanning)
    -s, --single-project   Path to a single MuleSoft project to scan
    -r, --report-dir       Directory to store HTML reports (default: ./reports)
    -p, --python-path      Path to Python executable (auto-detected if not specified)
    -h, --help            Show this help message

EXAMPLES:
    # Scan all projects in a directory
    $0 -d "/home/user/projects/mulesoft"
    $0 -d "/home/user/projects/mulesoft" -r "/home/user/reports"
    $0 -d "/home/user/projects/mulesoft" -p "/usr/bin/python3"
    
    # Scan a single project
    $0 -s "/home/user/projects/mulesoft/my-project"
    $0 -s "/home/user/projects/mulesoft/my-project" -r "/home/user/reports"
    $0 -s "/home/user/projects/mulesoft/my-project" -p "/usr/bin/python3"
EOF
}

# Function to detect Python executable
find_python_executable() {
    local python_commands=("python3" "python" "py")
    
    for cmd in "${python_commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            local version=$($cmd --version 2>&1)
            echo "Found Python: $cmd ($version)" >&2
            echo "$cmd"
            return 0
        fi
    done
    
    # Try common installation paths
    local common_paths=(
        "/usr/bin/python3"
        "/usr/bin/python"
        "/usr/local/bin/python3"
        "/usr/local/bin/python"
        "/opt/python*/bin/python3"
        "/opt/python*/bin/python"
    )
    
    for path_pattern in "${common_paths[@]}"; do
        for python_exe in $path_pattern; do
            if [[ -x "$python_exe" ]]; then
                local version=$($python_exe --version 2>&1)
                if [[ $? -eq 0 ]]; then
                    echo "Found Python: $python_exe ($version)" >&2
                    echo "$python_exe"
                    return 0
                fi
            fi
        done
    done
    
    return 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--projects-dir)
            PROJECTS_DIR="$2"
            shift 2
            ;;
        -s|--single-project)
            SINGLE_PROJECT="$2"
            shift 2
            ;;
        -r|--report-dir)
            REPORT_DIR="$2"
            shift 2
            ;;
        -p|--python-path)
            PYTHON_PATH="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}" >&2
            show_help
            exit 1
            ;;
    esac
done

# Validate that at least one scanning mode is specified
if [[ -z "$PROJECTS_DIR" && -z "$SINGLE_PROJECT" ]]; then
    echo -e "${RED}Error: Either -d (projects directory) or -s (single project) must be specified.${NC}" >&2
    show_help
    exit 1
fi

# Validate that only one scanning mode is specified
if [[ -n "$PROJECTS_DIR" && -n "$SINGLE_PROJECT" ]]; then
    echo -e "${RED}Error: Cannot specify both -d (projects directory) and -s (single project). Use only one scanning mode.${NC}" >&2
    show_help
    exit 1
fi

# Validate input based on scanning mode
if [[ -n "$PROJECTS_DIR" ]]; then
    if [[ ! -d "$PROJECTS_DIR" ]]; then
        echo -e "${RED}Error: Projects directory does not exist: $PROJECTS_DIR${NC}" >&2
        exit 1
    fi
else
    if [[ ! -d "$SINGLE_PROJECT" ]]; then
        echo -e "${RED}Error: Single project path does not exist: $SINGLE_PROJECT${NC}" >&2
        exit 1
    fi
fi

# Detect Python executable if not provided
if [[ -z "$PYTHON_PATH" ]]; then
    PYTHON_PATH=$(find_python_executable)
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: Python executable not found. Please install Python or specify the path with -p parameter.${NC}" >&2
        exit 1
    fi
else
    # Validate provided Python path
    if [[ ! -x "$PYTHON_PATH" ]]; then
        echo -e "${RED}Error: Python executable not found at specified path: $PYTHON_PATH${NC}" >&2
        exit 1
    fi
fi

# Python module to invoke (for correct relative imports)
PYTHON_MODULE="mule_validator.main"

# Create report directory if it doesn't exist
if [[ ! -d "$REPORT_DIR" ]]; then
    mkdir -p "$REPORT_DIR"
    echo "Created report directory: $REPORT_DIR"
fi

# Get absolute paths
PROJECTS_DIR=$(realpath "$PROJECTS_DIR")
REPORT_DIR=$(realpath "$REPORT_DIR")

echo -e "${YELLOW}Starting MuleSoft project scan...${NC}"
if [[ -n "$PROJECTS_DIR" ]]; then
    echo "Scan Mode: Batch scanning all projects"
    echo "Projects Directory: $PROJECTS_DIR"
else
    echo "Scan Mode: Single project scanning"
    echo "Project Path: $SINGLE_PROJECT"
fi
echo "Report Directory: $REPORT_DIR"
echo "Python Executable: $PYTHON_PATH"
echo ""

SUCCESS_COUNT=0
FAILURE_COUNT=0

# Function to process a single project
process_single_project() {
    local project_path="$1"
    local report_dir="$2"
    local python_exe="$3"
    
    local project_name=$(basename "$project_path")
    local report_file="${project_name}-mule_report.html"
    local report_path="$report_dir/$report_file"

    echo -e "${CYAN}Processing: $project_name${NC}"
    
    if "$python_exe" -m "$PYTHON_MODULE" "$project_path" --report-file "$report_path"; then
        echo -e "${GREEN}✓ Report generated: $report_path${NC}"
        return 0
    else
        echo -e "${RED}✗ Validation failed for $project_name (exit code: $?)${NC}"
        return 1
    fi
}

# Main processing logic
if [[ -n "$PROJECTS_DIR" ]]; then
    # Batch scanning mode
    for repo_path in "$PROJECTS_DIR"/*/; do
        if [[ ! -d "$repo_path" ]]; then
            continue
        fi
        
        repo_name=$(basename "$repo_path")
        report_file="${repo_name}-mule_report.html"
        report_path="$REPORT_DIR/$report_file"

        echo -e "${CYAN}Processing: $repo_name${NC}"
        
        if "$PYTHON_PATH" -m "$PYTHON_MODULE" "$repo_path" --report-file "$report_path"; then
            echo -e "${GREEN}✓ Report generated: $report_path${NC}"
            ((SUCCESS_COUNT++))
        else
            echo -e "${RED}✗ Validation failed for $repo_name (exit code: $?)${NC}"
            ((FAILURE_COUNT++))
        fi
        
        echo ""
    done
else
    # Single project scanning mode
    if process_single_project "$SINGLE_PROJECT" "$REPORT_DIR" "$PYTHON_PATH"; then
        SUCCESS_COUNT=1
        FAILURE_COUNT=0
    else
        SUCCESS_COUNT=0
        FAILURE_COUNT=1
    fi
    echo ""
fi

# Summary
echo -e "${YELLOW}Scan completed!${NC}"
echo -e "${GREEN}Successful: $SUCCESS_COUNT${NC}"
echo -e "${RED}Failed: $FAILURE_COUNT${NC}"
