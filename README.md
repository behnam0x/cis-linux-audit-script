🔐 CIS Linux Audit Script

This repository contains a comprehensive script to perform a full CIS (Center for Internet Security) benchmark audit for RHEL-based and Debian-based Linux distributions. It automates the process of checking system compliance with CIS security standards, helping system administrators and security professionals harden their systems effectively.
📋 What Is CIS Benchmark?

The CIS Benchmarks are best-practice security configuration guides developed by cybersecurity experts. They provide detailed recommendations for securing systems, applications, and networks. This script focuses on the CIS benchmarks for:

    RHEL-based systems (e.g., RHEL, CentOS, Rocky Linux, AlmaLinux)

    Debian-based systems (e.g., Debian, Ubuntu)

🚀 Features

    ✅ Covers all major CIS audit checks (authentication, logging, permissions, services, etc.)

    🧠 Detects system type and applies relevant checks

    📦 Modular and easy to extend

    📄 Generates detailed audit reports

    🔄 Supports dry-run and fix modes

📦 Supported Platforms
Distribution	Version(s)
RHEL	7, 8, 9
CentOS	7, 8
Oracle Linux 8, 9
Rocky Linux	8, 9
AlmaLinux	8, 9
Debian	10, 11
Ubuntu	18.04, 20.04, 22.04, 24.04
🛠️ How to Use

<pre lang="markdown">
git clone https://github.com/behnam0x/cis-linux-audit-script.git
cd cis-linux-audit-script/script
chmod +x AuditCISHardening.sh
sudo ./AuditCISHardening.sh
</pre>

📑 Checklist Overview

The script checks and optionally remediates the following categories:

    🔐 Authentication & Password Policies

    📁 File Permissions & Ownership

    🔍 Logging & Auditing

    🧱 Firewall & Network Configuration

    🧹 Unused Services & Packages

    🧾 System Updates & Patch Management

    🧬 Kernel Parameters & Sysctl Settings

    🧑‍💻 User Accounts & Access Controls

Each check is mapped to its corresponding CIS control ID (e.g., 1.1.1, 5.2.3) for easy cross-reference.

📊 Sample Output
<pre lang="markdown">
[✔] 1.1.1 Ensure mounting of cramfs filesystems is disabled
[✘] 1.1.2 Ensure mounting of squashfs filesystems is disabled
[✔] 5.2.3 Ensure password expiration is 365 days or less
...
</pre>
📚 References

[CIS Benchmark](https://www.cisecurity.org/cis-benchmarks/)
[RHEL Security Guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10#Security)

🤝 Contributing
Pull requests are welcome! If you want to add new checks, improve compatibility, or enhance reporting, feel free to contribute.

📄 License
This project is licensed under the MIT License. See the 


  
