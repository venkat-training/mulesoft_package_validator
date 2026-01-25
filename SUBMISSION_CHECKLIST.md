# 🏁 MuleSoft Package Validator – Final Submission Checklist

This checklist ensures that the project is complete, fully tested, and ready for submission.

---

## 1️⃣ Project Structure Verification

- [ ] `mule_validator/` folder contains all validator modules:
  - `api_validator.py`
  - `flow_validator.py`
  - `dependency_validator.py`
  - `mule_orphan_checker.py`
  - Other helper modules as needed
- [ ] `mule_validator_cli.py` exists and runs without errors
- [ ] `cli/` folder contains Copilot integration:
  - `copilot_entry.py`
  - `prompts.md`
- [ ] `tests/` folder contains all unit tests:
  - `test_api_validator.py`
  - `test_hybrid_suite.py`
- [ ] `reports/` folder (created automatically when generating HTML reports)
- [ ] HTML report template exists:
  - `mule_validator/report_template.html`

---

## 2️⃣ Testing

- [ ] Run all tests:

```bash
python -m unittest discover tests
python -m unittest tests/test_hybrid_suite.py
python -m unittest tests/test_api_validator.py
