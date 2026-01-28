# 📦 Sample Reports and Test Project

This directory contains sample validation reports and a test MuleSoft project.

## 📊 Sample Reports

### [mule_validator_report.html](mule_validator_report.html)
Complete validation report showing:
- 🔐 Security warnings (hardcoded credentials detected)
- 📊 Flow complexity metrics
- 📦 Dependency analysis
- ⚙️ Configuration validation
- 🔍 Code quality issues

**Open this file in your browser** to see a full example of the validator's output.

### [orphan_report.html](orphan_report.html)
Dedicated report for orphaned components:
- Unreferenced flows and sub-flows
- Unused configuration objects
- Dead error handlers
- Visualization of component relationships

**Open this file in your browser** to see orphan detection in action.

---

## 🧪 Sample MuleSoft Project

### [sample-mule-project/](sample-mule-project/)

A realistic MuleSoft application designed to demonstrate the validator's capabilities.

**Project Structure:**
```
sample-mule-project/
├── src/main/mule/
│   ├── api-main.xml           # Main API flows
│   ├── error-handlers.xml     # Error handling flows
│   └── utility-flows.xml      # Reusable sub-flows
├── src/main/resources/
│   ├── config-dev.yaml        # Development configuration
│   ├── config-prod.yaml       # Production configuration
│   └── api/api-spec.raml      # API specification
└── pom.xml                    # Maven dependencies
```

**Intentional Issues (for testing):**
- 🔴 Hardcoded password in `config-prod.yaml`
- 🔴 API key in `config-dev.yaml`
- 🟡 Orphaned flow `unusedValidationFlow`
- 🟡 Excessive logger components in `api-main.xml`
- 🟡 Flow complexity exceeding thresholds
- 🟡 Unused dependency in `pom.xml`

These issues are **intentionally included** to demonstrate the validator's detection capabilities.

---

## 🚀 How to Use

### Run Validation

From the repository root:

```bash
# Basic validation
python -m mule_validator_cli --project ./samples/sample-mule-project
```

### Generate Reports

```bash
# Generate HTML report
python -m mule_validator_cli \
  --project ./samples/sample-mule-project \
  --output my_report.html

# Generate both validation and orphan reports
python -m mule_validator_cli \
  --project ./samples/sample-mule-project \
  --output my_report.html \
  --orphan-report-file my_orphan_report.html
```

### Expected Output

When you run the validator on the sample project, you should see:

```
================================================================================
VALIDATION REPORT
================================================================================

--- SECURITY WARNINGS ---
  ⚠️  YAML Secret detected in config-prod.yaml
      Location: database.password
      Value: "hardcoded_password_123"
  
  ⚠️  YAML Secret detected in config-dev.yaml
      Location: api.key
      Value: "sk_test_abc123..."

--- FLOW VALIDATION ---
  ✅ Flows: 8 (limit: 100)
  ⚠️  High complexity flow: processOrderFlow (45 components)
  
--- ORPHAN DETECTION ---
  ⚠️  Orphaned flow: unusedValidationFlow
  ⚠️  Unreferenced sub-flow: helperSubFlow

--- DEPENDENCY ANALYSIS ---
  ⚠️  Unused dependency detected: commons-lang3

TOTAL WARNINGS: 6
================================================================================
```

---

## 📖 Learning Resources

Use this sample project to:

1. **Understand the validator** - See real-world issues detected
2. **Test modifications** - Add your own validation rules
3. **Benchmark performance** - Measure validation speed
4. **Create test cases** - Use as a reference for your own projects
5. **Demo the tool** - Show colleagues what automated validation looks like

---

## 🔧 Modify the Sample

Feel free to experiment by:
- ✅ Adding more intentional issues to test detection
- ✅ Removing security warnings to verify clean validation passes
- ✅ Adjusting flow complexity to trigger different thresholds
- ✅ Adding new flows and testing orphan detection
- ✅ Modifying configuration files to test YAML validation
- ✅ Changing dependencies to test dependency analysis

### Example Modifications

**Add a new security issue:**
```yaml
# In config-dev.yaml, add:
aws:
  secret_key: "AKIAIOSFODNN7EXAMPLE"  # Will be detected
```

**Create an orphan flow:**
```xml
<!-- In utility-flows.xml, add a flow that's never referenced -->
<flow name="neverUsedFlow">
  <logger message="This flow is orphaned"/>
</flow>
```

**Test complexity limits:**
```bash
# Run with stricter limits
python -m mule_validator_cli \
  --project ./samples/sample-mule-project \
  --max-components 30  # Lower threshold to trigger warnings
```

---

## 📊 Compare Your Results

After running the validator:

1. **Open your generated report** in a browser
2. **Compare with** `mule_validator_report.html` in this directory
3. **Verify** you see the same warnings and metrics
4. **Check** the orphan report matches `orphan_report.html`

If your results match, the validator is working correctly! ✅

---

## 🎯 Testing Workflow

### Quick Test (< 1 minute)
```bash
cd /path/to/mulesoft_package_validator
python -m mule_validator_cli --project ./samples/sample-mule-project
```

### Full Test with Reports (< 2 minutes)
```bash
# Generate all reports
python -m mule_validator_cli \
  --project ./samples/sample-mule-project \
  --output test_validation_report.html \
  --orphan-report-file test_orphan_report.html

# Open reports in browser
# Windows: start test_validation_report.html
# Mac: open test_validation_report.html
# Linux: xdg-open test_validation_report.html
```

### Batch Processing Test
```bash
# Create multiple test projects
mkdir -p /tmp/test_projects
cp -r ./samples/sample-mule-project /tmp/test_projects/project1
cp -r ./samples/sample-mule-project /tmp/test_projects/project2

# Run batch validation
./scan_all_projects.sh -d /tmp/test_projects -r /tmp/reports
```

---

## 🤝 Contribute Sample Issues

Have a real-world MuleSoft validation issue we should detect? 

1. Fork the repository
2. Add the issue to `sample-mule-project/`
3. Document it in this README
4. Submit a Pull Request

We'd love to expand the sample project with more real-world scenarios!

---

## 📧 Questions?

If you have questions about the sample project or reports:
- [Open an issue](https://github.com/venkat-training/mulesoft_package_validator/issues)
- [Start a discussion](https://github.com/venkat-training/mulesoft_package_validator/discussions)

---

## 🎓 Additional Resources

### MuleSoft Best Practices
- [MuleSoft Documentation](https://docs.mulesoft.com/)
- [MuleSoft Community](https://help.mulesoft.com/)

### Related Tools
- [MUnit](https://docs.mulesoft.com/munit/) - Unit testing framework
- [APIkit](https://docs.mulesoft.com/apikit/) - API development toolkit

---

<div align="center">

**[⬆ Back to main README](../README.md)**

</div>