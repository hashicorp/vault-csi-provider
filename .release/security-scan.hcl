# Copyright IBM Corp. 2019, 2026
# SPDX-License-Identifier: BUSL-1.1

binary {
    go_stdlib  = true // Scan the Go standard library used to build the binary.
    go_modules = true // Scan the Go modules included in the binary.
    osv        = true // Use the OSV vulnerability database.
    oss_index  = true // And use OSS Index vulnerability database.

    secrets {
        all = true
    }
}

container {
  dependencies = true // Scan any installed packages for vulnerabilities.
  osv          = true // Use the OSV vulnerability database.

  secrets {
    all = true
  }

  triage {
    suppress {
        vulnerabilities = [
          // Addresses a false positive from scan (our security scanner)
          // Fixed by Red Hat in: https://access.redhat.com/errata/RHSA-2025:20181
          // ProdSec tracking the false positive in: https://hashicorp.atlassian.net/browse/PSP-3514
          "CVE-2025-6020",
          // ncurses-base - fix is present in UBI 10.1 changelog (backported)
          "CVE-2025-69720",
          // glibc - CVE not explicitly listed in UBI 10.1 changelog; no patched version available
          "CVE-2025-15281",
          "CVE-2026-4046",
          // libcap - fix is present in UBI 10.1 changelog (backported)
          "CVE-2026-4878",
        ]
    }
  }
}
