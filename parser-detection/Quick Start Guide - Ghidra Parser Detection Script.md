# Quick Start Guide - Ghidra Parser Detection Script

## 5-Minute Setup

### Step 1: Install the Script
1. Download `ghidra_parser_detector.py`
2. Copy it to your Ghidra scripts directory:
   - **Windows**: `%USERPROFILE%\ghidra_scripts`
   - **Linux/macOS**: `~/ghidra_scripts`

### Step 2: Load Your Binary
1. Open Ghidra
2. Create a new project or open existing one
3. Import your target binary
4. Run auto-analysis (Analysis → Auto Analyze)
5. Wait for analysis to complete

### Step 3: Run the Script
1. Open Window → Script Manager
2. Find "ghidra_parser_detector.py" in the list
3. Double-click to run
4. Watch console output for progress

### Step 4: Review Results
- Check console output for detected functions
- Navigate to bookmarked functions using Bookmark Manager
- Review function comments for detection details

## Common Use Cases

### Network Protocol Analysis
```python
# Add to script or run separately
detector = ParserDetector()
detector.PARSING_KEYWORDS.extend([
    "packet", "frame", "protocol", "header", "payload"
])
detector.run_analysis()
```

### File Format Analysis
```python
# Add to script or run separately
detector = ParserDetector()
detector.PARSING_KEYWORDS.extend([
    "magic", "signature", "chunk", "block", "format"
])
detector.run_analysis()
```

### Quick Scan (Large Binaries)
```python
# Use built-in quick scan function
quick_scan()
```

## Understanding Output

### Confidence Levels
- **HIGH (70+ points)**: Very likely parser functions - start here
- **MEDIUM (40-69 points)**: Probable parsers - worth investigating
- **LOW (20-39 points)**: Possible parsers - review with caution

### Key Indicators
- **String references**: Functions using parsing-related strings
- **Loop patterns**: Functions with data processing loops
- **Field access**: Functions accessing structure fields sequentially
- **I/O calls**: Functions calling memory/I/O functions

## Troubleshooting

### No Functions Found
- Lower the score threshold (modify `get_minimum_score_threshold()`)
- Add custom keywords for your specific domain
- Ensure auto-analysis completed successfully

### Too Many Results
- Increase the score threshold
- Focus on HIGH confidence results only
- Use focused analysis on specific function patterns

### Script Errors
- Ensure Ghidra auto-analysis is complete
- Check that binary is properly loaded
- Verify script is in correct directory

## Next Steps

1. **Manual Validation**: Review high-confidence functions manually
2. **Cross-Reference Analysis**: Use Ghidra's xref features on detected functions
3. **Dynamic Analysis**: Correlate with debugging/runtime analysis
4. **Custom Configuration**: Adapt script for your specific use case

## Advanced Features

### Generate Reports
```python
# After running analysis
report_gen = ReportGenerator(detector.detected_functions)
report_gen.generate_html_report("/tmp/parser_report.html")
report_gen.generate_csv_report("/tmp/parser_report.csv")
```

### Custom Scoring
```python
# Modify ParserDetectorConfig class
class MyConfig(ParserDetectorConfig):
    @staticmethod
    def get_minimum_score_threshold():
        return 25  # Higher threshold
```

### Focused Analysis
```python
# Analyze only functions matching pattern
focused_scan(r".*parse.*")  # Functions with "parse" in name
```

## Tips for Success

1. **Start with defaults** - Run basic analysis first
2. **Review high confidence** - Focus on scores 70+
3. **Validate manually** - Always confirm with manual analysis
4. **Iterate and refine** - Adjust configuration based on results
5. **Use bookmarks** - Navigate efficiently using created bookmarks

## Support and Customization

- Modify `PARSING_KEYWORDS` for domain-specific terms
- Adjust `IO_FUNCTIONS` for custom I/O operations
- Change scoring thresholds in `ParserDetectorConfig`
- Add custom analysis patterns in `AdvancedPatternAnalyzer`

For detailed documentation, see `README.md` and `usage_examples.py`.

