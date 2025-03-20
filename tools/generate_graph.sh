#!/bin/bash

# Script to generate and view call graphs from AVR Stack Analyzer with vertical orientation

if [ $# -lt 1 ]; then
    echo "Usage: $0 <elf_file> [options]"
    echo "Generates a call graph visualization from an ELF file"
    echo "Options:"
    echo "  --view       Open the generated graph automatically"
    echo "  --svg        Generate SVG format (better for large graphs)"
    echo "  --png        Generate PNG format"
    echo "  --pdf        Generate PDF format"
    echo "  --vertical   Force vertical orientation (default)"
    echo "  --horizontal Change to horizontal orientation"
    exit 1
fi

ELF_FILE=$1
VIEW_GRAPH=0
GEN_SVG=0
GEN_PNG=0
GEN_PDF=0
ORIENTATION="TB"  # Default to Top-Bottom (vertical)

# Parse options
shift
while [ "$#" -gt 0 ]; do
    case "$1" in
        --view) VIEW_GRAPH=1 ;;
        --svg) GEN_SVG=1 ;;
        --png) GEN_PNG=1 ;;
        --pdf) GEN_PDF=1 ;;
        --vertical) ORIENTATION="TB" ;;
        --horizontal) ORIENTATION="LR" ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Default to SVG and PNG if no format specified
if [ $GEN_SVG -eq 0 ] && [ $GEN_PNG -eq 0 ] && [ $GEN_PDF -eq 0 ]; then
    GEN_SVG=1
    GEN_PNG=1
fi

# Check if dot is installed
if ! command -v dot &> /dev/null; then
    echo "GraphViz 'dot' command not found. Please install GraphViz:"
    echo "  sudo apt-get install graphviz"
    exit 1
fi

# Check if avr_stack is in PATH, otherwise use local build
if command -v avr_stack &> /dev/null; then
    AVR_STACK="avr_stack"
else
    AVR_STACK="./target/release/avr_stack"
    
    if [ ! -f "$AVR_STACK" ]; then
        echo "AVR Stack Analyzer not found. Building..."
        cargo build --release
    fi
fi

# Generate base filename
BASE_NAME=$(basename "$ELF_FILE" | cut -f1 -d.)
DOT_FILE="${BASE_NAME}.dot"
SVG_FILE="${BASE_NAME}.svg"
PNG_FILE="${BASE_NAME}.png"
PDF_FILE="${BASE_NAME}.pdf"

echo "Analyzing $ELF_FILE..."
"$AVR_STACK" --call-graph "$ELF_FILE"

if [ -f "$DOT_FILE" ]; then
    # Configure dot options for better graph layout
    if [ "$ORIENTATION" = "TB" ]; then
        DOT_OPTS="-Grankdir=TB -Gsize=8.5,11 -Gratio=fill"
        echo "Using vertical (top-to-bottom) layout"
    else
        DOT_OPTS="-Grankdir=LR -Gsize=11,8.5 -Gratio=fill"
        echo "Using horizontal (left-to-right) layout"
    fi
    
    # Common options for all formats
    COMMON_OPTS="-Gsplines=true -Goverlap=false -Gconcentrate=true"
    
    # Generate requested formats
    if [ $GEN_SVG -eq 1 ]; then
        echo "Generating SVG..."
        dot $DOT_OPTS $COMMON_OPTS -Tsvg "$DOT_FILE" -o "$SVG_FILE"
        echo "  Created $SVG_FILE"
    fi
    
    if [ $GEN_PNG -eq 1 ]; then
        echo "Generating PNG..."
        dot $DOT_OPTS $COMMON_OPTS -Tpng "$DOT_FILE" -o "$PNG_FILE"
        echo "  Created $PNG_FILE"
    fi
    
    if [ $GEN_PDF -eq 1 ]; then
        echo "Generating PDF..."
        dot $DOT_OPTS $COMMON_OPTS -Tpdf "$DOT_FILE" -o "$PDF_FILE"
        echo "  Created $PDF_FILE"
    fi
    
    echo "Generated DOT file: $DOT_FILE"
    
    if [ $VIEW_GRAPH -eq 1 ]; then
        # Choose which file to view (prefer SVG)
        if [ -f "$SVG_FILE" ]; then
            VIEW_FILE="$SVG_FILE"
        elif [ -f "$PNG_FILE" ]; then
            VIEW_FILE="$PNG_FILE"
        elif [ -f "$PDF_FILE" ]; then
            VIEW_FILE="$PDF_FILE"
        else
            VIEW_FILE="$DOT_FILE"
        fi
        
        # Try to open the graph with an appropriate viewer
        echo "Opening $VIEW_FILE for viewing..."
        if command -v xdg-open &> /dev/null; then
            xdg-open "$VIEW_FILE"
        elif command -v open &> /dev/null; then
            open "$VIEW_FILE"
        else
            echo "Cannot open image automatically. Please open manually."
        fi
    fi
else
    echo "Error: Failed to generate call graph"
    exit 1
fi

echo "Done!"
