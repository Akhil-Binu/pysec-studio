# Contributing to PySecStudio

Thank you for your interest in contributing to **PySecStudio**! We welcome contributions from developers, security researchers, DevSecOps engineers, and community members.

Please review this guide before submitting issues or pull requests.

---

## 🛠️ Local Development Setup

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- **Python**: v3.8+ (for testing generated security automation scripts)
- **Git**

### Installation
1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/pysec-studio.git
   cd pysec-studio
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the local development server:
   ```bash
   npm run dev
   ```
5. Open [http://localhost:5173/](http://localhost:5173/) in your browser.

---

## 🧪 Testing & Validation

Before opening a pull request, ensure that your changes pass all build and linting checks:

```bash
# Verify TypeScript compilation and production build
npm run build
```

If you add new Python script templates or code generators:
1. Ensure the Python scripts are PEP 8 compliant.
2. Verify that they execute cleanly under Python 3.8+ using only standard library modules where possible.
3. Test edge cases (timeout handling, invalid socket addresses, malformed log lines).

---

## 📝 Commit Message Conventions

We adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` Adds a new feature or capability (e.g., `feat: add AWS GuardDuty JSON log parser`)
- `fix:` Patches a bug or addresses an issue (e.g., `fix: resolve regex backtracking on nginx logs`)
- `docs:` Documentation or guideline updates (e.g., `docs: update security scanning guidelines`)
- `style:` Formatting, whitespace, or visual design refinements
- `refactor:` Code restructuring without behavioral changes
- `test:` Adding or updating tests
- `chore:` Maintenance tasks, dependency bumps, or build pipeline tweaks

---

## 🚀 Pull Request Workflow

1. **Create a branch**:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. **Commit your changes**:
   ```bash
   git commit -m "feat: describe your enhancement concisely"
   ```
3. **Push to your fork**:
   ```bash
   git push origin feat/your-feature-name
   ```
4. **Open a Pull Request**:
   - Provide a clear summary of what changes were made.
   - Reference any related issues (e.g., `Closes #12`).
   - Include screenshots or test outputs where applicable.

---

## ⚖️ Code of Conduct

All contributors are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat others with respect and empathy.
