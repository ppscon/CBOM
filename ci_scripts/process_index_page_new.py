#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def replace_variables(text):
    """
    Replace shell-style variables in text with their actual values.
    
    Args:
        text (str): Text containing variables to replace
        
    Returns:
        str: Text with variables replaced
    """
    if not text:
        return text
    
    # Replace ${GITHUB_SHA} with the actual commit SHA
    github_sha = os.environ.get('GITHUB_SHA', 'Unknown commit')
    text = re.sub(r'\${GITHUB_SHA}', github_sha, text)
    
    # Replace $(date) with the actual date
    current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    text = re.sub(r'\$\(date\)', current_date, text)
    
    return text

def process_index_page(input_file, output_file=None):
    """
    Process the index page, replacing shell variables with their values.
    
    Args:
        input_file (str): Path to the input index.html file
        output_file (str, optional): Path where the processed file should be saved. 
                                     If None, overwrites the input file.
    """
    try:
        # If output_file is not specified, use the input file
        if output_file is None:
            output_file = input_file
            
        # Read the input file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        logging.info(f"Read index page from {input_file}")
        
        # Replace variables
        processed_content = replace_variables(content)
        
        # Check if any replacements were made
        if processed_content == content:
            logging.warning("No variables were replaced in the index page")
        else:
            logging.info("Successfully replaced variables in the index page")
        
        # Write the output file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(processed_content)
            
        logging.info(f"Processed index page saved to {output_file}")
        
        return True
        
    except Exception as e:
        logging.error(f"Error processing index page: {str(e)}")
        logging.error(f"Exception details: {str(e.__class__.__name__)}: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        return False

def main():
    parser = argparse.ArgumentParser(description='Process index.html page, replacing shell variables with their values')
    parser.add_argument('input_file', help='Path to the input index.html file')
    parser.add_argument('--output-file', help='Path where the processed file should be saved. If not specified, overwrites the input file')
    
    args = parser.parse_args()
    
    success = process_index_page(args.input_file, args.output_file)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 