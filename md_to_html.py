#!/usr/bin/env python3
"""
Enhanced script to convert markdown to HTML with beautiful syntax highlighting
"""

import markdown
from pathlib import Path
from pygments.styles import get_style_by_name
from pygments.formatters import HtmlFormatter

def convert_md_to_html(input_file: str, output_file: str = None):
    """Convert markdown file to HTML with enhanced styling and syntax highlighting"""
    
    # Set default output file if not provided
    if output_file is None:
        input_path = Path(input_file)
        output_file = input_path.with_suffix('.html')
    
    # Read the markdown file
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            md_content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found")
        return False
    except Exception as e:
        print(f"Error reading file: {e}")
        return False
    
    # Convert markdown to HTML with extensions for better formatting (selective syntax highlighting)
    md = markdown.Markdown(extensions=[
        'tables',                    # Support for tables
        'fenced_code',              # Support for code blocks
        'toc',                      # Table of contents
        'codehilite',               # Syntax highlighting
        'attr_list',                # Support for attributes
        'def_list',                 # Definition lists
        'footnotes',                # Footnotes
        'admonition'                # Admonitions/callouts
    ], extension_configs={
        'codehilite': {
            'css_class': 'highlight',
            'use_pygments': True,
            'guess_lang': False,        # Don't auto-guess language
            'linenums': False
        },
        'toc': {
            'permalink': True,
            'permalink_class': 'toc-permalink',
            'permalink_title': 'Link to this section'
        }
    })
    
    html_content = md.convert(md_content)
    
    # Get the table of contents
    toc = md.toc if hasattr(md, 'toc') else ""
    
    # Generate Pygments CSS for Python syntax highlighting only
    formatter = HtmlFormatter(style='default', cssclass='highlight')
    pygments_css = formatter.get_style_defs('.highlight')
    
    # Create complete HTML document with minimal styling
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cybersecurity Copilot - Technical Documentation</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
        }}
        
        .content-wrapper {{
            display: grid;
            grid-template-columns: 250px 1fr;
            gap: 40px;
        }}
        
        .toc-sidebar {{
            position: sticky;
            top: 20px;
            height: fit-content;
        }}
        
        .toc-title {{
            font-weight: bold;
            margin-bottom: 15px;
            font-size: 1.1em;
        }}
        
        .toc ul {{
            list-style: none;
            padding-left: 0;
            margin: 0;
        }}
        
        .toc ul ul {{
            padding-left: 15px;
            margin-top: 5px;
        }}
        
        .toc li {{
            margin-bottom: 5px;
        }}
        
        .toc a {{
            color: #333;
            text-decoration: none;
            font-size: 0.9em;
        }}
        
        .toc a:hover {{
            text-decoration: underline;
        }}
        
        h1, h2, h3, h4, h5, h6 {{
            color: #333;
            margin-top: 30px;
            margin-bottom: 15px;
        }}
        
        h1 {{
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }}
        
        h2 {{
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }}
        
        .toc-permalink {{
            opacity: 0;
            margin-left: 5px;
            color: #999;
        }}
        
        h1:hover .toc-permalink,
        h2:hover .toc-permalink,
        h3:hover .toc-permalink,
        h4:hover .toc-permalink,
        h5:hover .toc-permalink,
        h6:hover .toc-permalink {{
            opacity: 1;
        }}
        
        /* Python code blocks with syntax highlighting */
        {pygments_css}
        
        .highlight {{
            margin: 20px 0;
            border-radius: 4px;
            overflow: hidden;
        }}
        
        .highlight pre {{
            margin: 0;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
        }}
        
        /* Plain code blocks (no language specified) */
        pre:not(.highlight) {{
            background-color: #f5f5f5;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
            color: #333;
        }}
        
        /* Inline code */
        code {{
            background-color: #f5f5f5;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
            color: #333;
        }}
        
        /* Code inside highlighted blocks */
        .highlight code {{
            background-color: transparent;
            padding: 0;
            color: inherit;
        }}
        
        /* Plain pre code blocks */
        pre:not(.highlight) code {{
            background-color: transparent;
            padding: 0;
        }}
        
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        
        th, td {{
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
        }}
        
        th {{
            background-color: #f5f5f5;
            font-weight: bold;
        }}
        
        blockquote {{
            border-left: 3px solid #ddd;
            margin: 20px 0;
            padding-left: 20px;
            font-style: italic;
        }}
        
        @media (max-width: 768px) {{
            .content-wrapper {{
                grid-template-columns: 1fr;
            }}
            
            .toc-sidebar {{
                position: static;
            }}
        }}
    </style>
</head>
<body>
    <div class="content-wrapper">
        <div class="toc-sidebar">
            <div class="toc-title">Table of Contents</div>
            <div class="toc">
                {toc}
            </div>
        </div>
        <div class="main-content">
            {html_content}
        </div>
    </div>
</body>
</html>"""
    
    # Write the HTML file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_html)
        print(f"Successfully converted '{input_file}' to '{output_file}'")
        return True
    except Exception as e:
        print(f"Error writing HTML file: {e}")
        return False

def main():
    """Main function"""
    input_file = "cymotive_ex.md"
    output_file = "index.html"
    
    print(f"Converting {input_file} to HTML...")
    success = convert_md_to_html(input_file, output_file)
    
    if success:
        print(f"✅ Conversion complete! Open '{output_file}' in your browser to view the result.")
    else:
        print("❌ Conversion failed!")

if __name__ == "__main__":
    main()