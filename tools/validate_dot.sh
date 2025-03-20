#!/bin/bash

# Script to validate DOT files to ensure they're correctly formatted

if [ $# -lt 1 ]; then
    echo "Usage: $0 <dot_file>"
    echo "Validates a DOT file to ensure proper syntax"
    exit 1
fi

DOT_FILE=$1

# Check if the file exists
if [ ! -f "$DOT_FILE" ]; then
    echo "Error: File '$DOT_FILE' not found."
    exit 1
fi

# Check if dot is installed
if ! command -v dot &> /dev/null; then
    echo "GraphViz 'dot' command not found. Please install GraphViz:"
    echo "  sudo apt-get install graphviz"
    exit 1
fi

# Validate the DOT file syntax
echo "Validating DOT file: $DOT_FILE"
# Use dot with -v flag but discard the verbose output - it will exit with error if syntax is wrong
if dot -v -o /dev/null "$DOT_FILE" 2>/dev/null; then
    echo "✓ DOT file is valid."
else
    echo "✗ DOT file has syntax errors."
    
    # Try to identify the line number with the error
    DOT_OUTPUT=$(dot -v -o /dev/null "$DOT_FILE" 2>&1)
    if echo "$DOT_OUTPUT" | grep -q "line"; then
        ERROR_LINE=$(echo "$DOT_OUTPUT" | grep "line" | head -1)
        echo "Error details: $ERROR_LINE"
        
        # Extract line number
        LINE_NUM=$(echo "$ERROR_LINE" | grep -oE "line [0-9]+" | grep -oE "[0-9]+")
        if [ -n "$LINE_NUM" ]; then
            echo "Error around line $LINE_NUM:"
            # Show a few lines around the error
            START=$((LINE_NUM - 2))
            if [ $START -lt 1 ]; then START=1; fi
            END=$((LINE_NUM + 2))
            sed -n "${START},${END}p" "$DOT_FILE" | nl -v "$START"
        fi
    else
        echo "Couldn't identify the exact error location."
    fi
    
    # Offer to fix common issues automatically
    echo
    echo "Would you like to try automatic fixes? (y/n)"
    read -r ANSWER
    if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
        # Backup the original file
        cp "$DOT_FILE" "${DOT_FILE}.bak"
        
        # Apply common fixes
        echo "Applying fixes to $DOT_FILE..."
        
        # Fix missing semicolons after attributes
        sed -i 's/\]\([^;]\)/\];/g' "$DOT_FILE"
        
        # Fix unescaped quotes in labels
        sed -i 's/label="\([^"]*\)""/label="\1\\""/' "$DOT_FILE"
        
        # Fix invalid node names
        sed -i 's/\<\([a-zA-Z0-9_]*\)[ -]\([a-zA-Z0-9_]*\)\>/"\1_\2"/g' "$DOT_FILE"
        
        # Fix unclosed braces
        OPEN_BRACES=$(grep -o "{" "$DOT_FILE" | wc -l)
        CLOSE_BRACES=$(grep -o "}" "$DOT_FILE" | wc -l)
        if [ "$OPEN_BRACES" -gt "$CLOSE_BRACES" ]; then
            DIFF=$((OPEN_BRACES - CLOSE_BRACES))
            for i in $(seq 1 $DIFF); do
                echo "}" >> "$DOT_FILE"
            fi
            echo "Added $DIFF missing closing braces."
        fi
        
        # Validate again
        if dot -v -o /dev/null "$DOT_FILE" 2>/dev/null; then
            echo "✓ Fixes successful! DOT file is now valid."
        else
            echo "✗ Automatic fixes didn't resolve all issues."
            echo "You may need to edit the file manually or regenerate it."
            # Restore original file
            mv "${DOT_FILE}.bak" "$DOT_FILE"
        fi
    fi
    
    exit 1
fi

# Generate image if requested
echo
echo "Would you like to generate a PNG image from this DOT file? (y/n)"
read -r ANSWER
if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
    BASE_NAME=$(basename "$DOT_FILE" .dot)
    PNG_FILE="${BASE_NAME}.png"
    
    echo "Generating $PNG_FILE..."
    dot -Tpng "$DOT_FILE" -o "$PNG_FILE"
    
    if [ -f "$PNG_FILE" ]; then
        echo "✓ Successfully generated $PNG_FILE"
        
        # Try to display the image
        if command -v xdg-open &> /dev/null; then
            echo "Opening image..."
            xdg-open "$PNG_FILE"
        elif command -v open &> /dev/null; then
            echo "Opening image..."
            open "$PNG_FILE"
        else
            echo "Image viewer not found. Please open $PNG_FILE manually."
        fi
    else
        echo "✗ Failed to generate PNG image."
    fi
fi

echo "Done!"
