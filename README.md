# AWS Resource Misconfiguration Scanner

A Python-based tool to identify common misconfigurations in your AWS environment. Designed for security audits, DevSecOps pipelines and niche blue team practice labs, but you can use it for whatever your beating heart desires. 💓

---

## Features

- ✅ Detects publicly accessible **S3 buckets**
- 🔐 Flags open **Security Groups** (e.g., `0.0.0.0/0` on ports 22, 3389, etc.)
- 🧊 Identifies **unencrypted EBS volumes**
- 🕵️ Scans **S3 objects for leaked credentials** (e.g., hardcoded AWS keys)
- 📋 Outputs **JSON** and **Markdown** reports
- 🎨 CLI-enhanced with [Rich](https://github.com/Textualize/rich)
- 📣 Optional **Slack alerts** for risky findings
- 🧪 Ready for CI/CD use with GitHub Actions

---

## Installation

```bash
git clone https://github.com/KenB773/AWSMisconfigScan.git
cd AWSMisconfigScan
pip install -r requirements.txt
