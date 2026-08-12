"""checkov_url_overrides.py — Shared canonical Checkov rule URL overrides.

Why this lives in its own module:
  Checkov OSS ships a `helpUri` for every rule that points to
  docs.prismacloud.io. That domain was acquired by Palo Alto in 2026 and
  the docs surface was retired; the per-rule deep-links now redirect to
  the generic cortex-docs.paloaltonetworks.com/appsec-rules landing page.

  This module is the single source of truth for the canonical GitHub
  source URL for every Checkov rule we care about. It is used by:

    1. aggregate.py — to rewrite the helpUri shown in the HTML report
       (and to dedupe the SAST rule table).

    2. rewrite_sarif_help.py — to rewrite the helpUri in every per-env
       SARIF on disk so CI pipelines that ingest SARIF directly also see
       the correct URL.

    3. scan.sh — to build a sed script that rewrites Checkov's
       console output so the operator's terminal does not show broken
       prismacloud.io links.

  Adding a new rule:
    1. Find the canonical GitHub source file
       (https://github.com/bridgecrewio/checkov/blob/main/<path>).
    2. Verify with `curl -sIL <raw_url>` returns 200.
    3. Add the entry to RULE_SOURCE_URLS below.
    4. The aggregator, SARIF rewriter, and shell filter pick it up
       automatically.

  Verification date for all entries: 2026-08-06 (HEAD 200 on
  raw.githubusercontent.com).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

# Lazy import: ID_PARTS_PATTERN comes from checkov.docs_generator, but the
# CI ``mapping-lint`` job runs without checkov installed (only pyyaml). A
# module-level import would break that job with ModuleNotFoundError. The
# import is deferred to the single function that uses it
# (``build_sed_filter``). Other call sites in this module -- the rule URL
# table, ``get_help_uri`` -- do not touch the regex at all.
if TYPE_CHECKING:
    from checkov.docs_generator import ID_PARTS_PATTERN  # noqa: F401

# Cloud prefix -> Checkov source directory name (under
# checkov/terraform/checks/resource/). This is the SINGLE source of truth
# for the mapping; do NOT maintain a parallel list anywhere else.
#
# Verified against Checkov's actual directory layout in
# checkov/terraform/checks/resource/ on 2026-08-12. Unknown clouds
# resolve to the repo root (no directory) — better a 200 on the tree view
# than a 404 on a guessed directory.
CLOUD_TO_DIR: Final[dict[str, str]] = {
    "AWS": "aws",
    "AZURE": "azure",
    "GCP": "gcp",
    "K8S": "kubernetes",
    "ALI": "alicloud",
    "DIO": "digitalocean",
    "GIT": "github",
    "GLB": "gitlab",
    "LIN": "linode",
    "NCP": "ncp",
    "OCI": "oci",
    "OKTA": "okta",
    "OPENSTACK": "openstack",
    "PAN": "panos",
    "TC": "tencentcloud",
    "YC": "yandexcloud",
}

# Canonical Checkov rule ID -> canonical GitHub source URL.
# 82 entries (verified 2026-08-12). 78 are CKV_AZURE_*/CKV2_AZURE_* (PCI-focused
# pack); the remaining 4 are CKV_SECRET_* (point to checkov/secrets/runner.py
# because those rules are loaded from Bridgecrew platform metadata rather than
# open-source source files) and 1 CKV_TF_1 (Terraform-generic).
#
# This table is the EXPLICIT OVERRIDE MAP for the per-rule canonical URLs used
# by aggregate.py and rewrite_sarif_help.py. It is NOT a fallback for the
# build_sed_filter() rewrite — that path derives the directory dynamically
# from the check ID's cloud prefix. The map is PCI/Azure-focused today and
# will be supplemented by AWS/GCP/K8s packs as those rule sets are reviewed.
RULE_SOURCE_URLS: dict[str, str] = {
    "CKV_AZURE_13": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceAuthentication.py",
    "CKV_AZURE_16": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentity.py",
    "CKV_AZURE_17": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceClientCertificate.py",
    "CKV_AZURE_18": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHttps20Enabled.py",
    "CKV_AZURE_23": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDetailedErrorMessages.py",
    "CKV_AZURE_24": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataLakeStoreEncryption.py",
    "CKV_AZURE_26": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerAuditingSettings.py",
    "CKV_AZURE_27": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAdmins.py",
    "CKV_AZURE_33": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageQueueServicesLoggingEnabled.py",
    "CKV_AZURE_34": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageBlobContainerPublicAccess.py",
    "CKV_AZURE_42": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultRecoverable.py",
    "CKV_AZURE_43": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountName.py",
    "CKV_AZURE_44": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountMinTlsVersion.py",
    "CKV_AZURE_52": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MSSQLMinTlsVersion.py",
    "CKV_AZURE_59": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountNoPublicAccess.py",
    "CKV_AZURE_63": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHTTPLogs.py",
    "CKV_AZURE_65": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDetailedErrorMessages.py",
    "CKV_AZURE_66": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceFailedRequestTracing.py",
    "CKV_AZURE_70": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppHttpsOnly.py",
    "CKV_AZURE_71": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentity.py",
    "CKV_AZURE_7": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPolicy.py",
    "CKV_AZURE_78": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceFtpsState.py",
    "CKV_AZURE_88": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceStorageAccount.py",
    "CKV_AZURE_89": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCachePublicNetworkAccessEnabled.py",
    "CKV_AZURE_103": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataFactoryUsesGitRepository.py",
    "CKV_AZURE_104": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataFactoryNoPublicNetworkAccess.py",
    "CKV_AZURE_110": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultEnablesPurgeProtection.py",
    "CKV_AZURE_113": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerPublicAccessDisabled.py",
    "CKV_AZURE_115": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSEnablesPrivateClusters.py",
    "CKV_AZURE_117": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSUsesDiskEncryptionSet.py",
    "CKV_AZURE_137": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRAdminAccountDisabled.py",
    "CKV_AZURE_139": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRPublicNetworkAccessDisabled.py",
    "CKV_AZURE_148": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCacheMinTLSVersion.py",
    "CKV_AZURE_153": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSlotHTTPSOnly.py",
    "CKV_AZURE_156": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MSSQLServerAuditPolicyLogMonitor.py",
    "CKV_AZURE_164": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRUseSignedImages.py",
    "CKV_AZURE_165": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRGeoreplicated.py",
    "CKV_AZURE_166": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACREnableImageQuarantine.py",
    "CKV_AZURE_167": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACREnableRetentionPolicy.py",
    "CKV_AZURE_168": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSMaxPodsMinimum.py",
    "CKV_AZURE_172": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSSecretStoreRotation.py",
    "CKV_AZURE_190": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageBlobRestrictPublicAccess.py",
    "CKV_AZURE_199": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusDoubleEncryptionEnabled.py",
    "CKV_AZURE_201": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusHasCMK.py",
    "CKV_AZURE_202": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusIdentityProviderEnabled.py",
    "CKV_AZURE_203": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusLocalAuthDisabled.py",
    "CKV_AZURE_204": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusVirtualNetworkEnabled.py",
    "CKV_AZURE_205": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusSubnetEnabled.py",
    "CKV_AZURE_206": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountReplication.py",
    "CKV_AZURE_212": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountHttpsOnly.py",
    "CKV_AZURE_213": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountPublicAccess.py",
    "CKV_AZURE_221": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPluginAzure.py",
    "CKV_AZURE_222": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPluginKubenet.py",
    "CKV_AZURE_224": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLDatabaseLedgerEnabled.py",
    "CKV_AZURE_225": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountImmutabilityPolicy.py",
    "CKV_AZURE_226": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSUsesRBAC.py",
    "CKV_AZURE_227": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSUsesAzureAD.py",
    "CKV_AZURE_229": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountLifecycleMgmtEnabled.py",
    "CKV_AZURE_232": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSPrivateCluster.py",
    "CKV_AZURE_233": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLDatabaseAuditingEnabled.py",
    "CKV_AZURE_237": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerAuditingEnabled.py",
    "CKV2_AZURE_1": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/StorageCriticalDataEncryptedCMK.yaml",
    "CKV2_AZURE_2": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VAisEnabledInStorageAccount.yaml",
    "CKV2_AZURE_3": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VAsetPeriodicScansOnSQL.yaml",
    "CKV2_AZURE_4": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VASendScanReportsTo.yaml",
    "CKV2_AZURE_5": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VASendEmailNotificationsToAdmins.yaml",
    "CKV2_AZURE_8": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/StorageContainerActivityLogsNotPubliclyAccessible.yaml",
    "CKV2_AZURE_20": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/StorageLoggingIsEnabledForTableService.yaml",
    "CKV2_AZURE_21": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/StorageLoggingIsEnabledForBlobService.yaml",
    "CKV2_AZURE_29": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureAKSclusterAzureCNIEnabled.yaml",
    "CKV2_AZURE_32": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureKeyVaultConfigPrivateEndpoint.yaml",
    "CKV2_AZURE_33": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccConfigWithPrivateEndpoint.yaml",
    "CKV2_AZURE_34": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureSQLserverNotOverlyPermissive.yaml",
    "CKV2_AZURE_38": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccountEnableSoftDelete.yaml",
    "CKV2_AZURE_40": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccConfigSharedKeyAuth.yaml",
    "CKV2_AZURE_41": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccConfig_SAS_expirePolicy.yaml",
    "CKV2_AZURE_45": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMSSQLserverConfigPrivEndpt.yaml",
    "CKV2_AZURE_47": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccConfigWithoutBlobAnonymousAccess.yaml",
    "CKV_SECRET_3": "https://github.com/bridgecrewio/checkov/blob/main/checkov/secrets/runner.py",
    "CKV_SECRET_6": "https://github.com/bridgecrewio/checkov/blob/main/checkov/secrets/runner.py",
    "CKV_SECRET_18": "https://github.com/bridgecrewio/checkov/blob/main/checkov/secrets/runner.py",
    "CKV_TF_1": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/module/generic/RevisionHash.py",
}


def __getattr__(name: str):
    """Lazy module-level attribute access.

    The CI ``mapping-lint`` job installs only pyyaml (no checkov), so
    the legacy ``from checkov.docs_generator import ID_PARTS_PATTERN``
    was moved out of the module top to keep that job green. Test
    consumers (and any code that wants to reuse the same regex)
    import ``ID_PARTS_PATTERN`` via ``from checkov_url_overrides
    import ID_PARTS_PATTERN``; this ``__getattr__`` keeps that
    public surface working without re-introducing the import-time
    dependency on checkov.
    """
    if name == "ID_PARTS_PATTERN":
        from checkov.docs_generator import ID_PARTS_PATTERN  # noqa: PLC0415
        return ID_PARTS_PATTERN
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_help_uri(rule_id: str, upstream_help_uri: str | None = None) -> str:
    """Return the canonical GitHub source URL for a Checkov rule.

    Args:
      rule_id: The Checkov rule ID (e.g. "CKV_AZURE_13").
      upstream_help_uri: The original helpUri from Checkov's SARIF. Used
        ONLY for unmapped rules that are not in our override table
        AND not docs.prismacloud.io (we deliberately do NOT fall
        back to prismacloud.io, even if Checkov emitted it, because
        that domain was retired in 2026 and the per-rule deep-links
        no longer resolve).

    Returns:
      The canonical GitHub URL if mapped. Otherwise, a best-effort
      GitHub URL or the upstream URI as a last resort.
    """
    if rule_id in RULE_SOURCE_URLS:
        return RULE_SOURCE_URLS[rule_id]
    # Upstream fallback: prefer the upstream URL ONLY if it isn't
    # the broken docs.prismacloud.io domain. If it is, we deliberately
    # fall through to the GitHub repo root instead of preserving a
    # dead link.
    if (
        upstream_help_uri
        and "docs.prismacloud.io" not in upstream_help_uri
        and "prismacloud.io" not in upstream_help_uri
    ):
        return upstream_help_uri
    # Last-resort fallback: Checkov's GitHub repo root.
    return "https://github.com/bridgecrewio/checkov"


def build_sed_filter(
    cloud_prefix: str | None = None,
    check_id: str | None = None,
) -> str:
    """Build a sed expression that rewrites Checkov's CLI output URLs.

    Returns a sed `s|...|...|g` expression that replaces any
    docs.prismacloud.io URL with a Checkov GitHub source-tree URL for the
    given cloud. The checkov CLI prints lines like:

        Guide: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/azure-policies/bc-azr-general-2

    The rule ID is NOT on the same line as the Guide URL, so we cannot
    do a per-rule rewrite via sed alone. Instead we replace the entire
    upstream base URL with a stable landing page that points operators
    at our canonical sources. The `Guide:` line ends with the broken
    prisma URL; we replace it with the Checkov GitHub source tree for
    the matching cloud directory (e.g. `checkov/terraform/checks/resource/aws/`)
    — or, for unknown clouds / no prefix, the repo root, which is always
    200 and lets the operator drill down to the rule file.

    Args:
      cloud_prefix: The Checkov cloud prefix (e.g. "AWS", "AZURE", "K8S").
        When `None` or unknown, the filter rewrites to the Checkov GitHub
        repo root.
      check_id: A full Checkov rule ID (e.g. "CKV_AZURE_13"). When
        provided, the cloud prefix is parsed from it via
        `ID_PARTS_PATTERN` (Checkov's canonical regex
        `r'([^_]*)_([^_]*)_(\d+)'`) and takes precedence over the
        `cloud_prefix` arg. This avoids re-defining the regex locally —
        the DRY/LIGHTWEIGHT rule (d) of the T11 plan.

    Returns:
      A sed substitution expression.

    For richer filtering (where the rule ID is in scope), the
    rewrite_sarif_help.py script does a per-rule rewrite on the SARIF.
    """
    upstream_anchor = r"https://docs\.prismacloud\.io/en/enterprise-edition/policy-reference/"
    repo_root = "https://github.com/bridgecrewio/checkov"
    # Parse the cloud prefix from check_id using Checkov's own regex
    # (DRY/LIGHTWEIGHT rule d — never redefine the pattern locally).
    # Imported lazily at top of file (see TYPE_CHECKING block) so this
    # module is importable in environments without checkov installed
    # (e.g. the CI ``mapping-lint`` job that only installs pyyaml).
    if check_id:
        from checkov.docs_generator import ID_PARTS_PATTERN  # noqa: PLC0415
        match = ID_PARTS_PATTERN.match(check_id)
        if match:
            cloud_prefix = match.group(2)
    if cloud_prefix and cloud_prefix in CLOUD_TO_DIR:
        target = f"{repo_root}/tree/main/checkov/terraform/checks/resource/{CLOUD_TO_DIR[cloud_prefix]}/"
    else:
        # Unknown cloud (or no prefix) -> Checkov repo root. Better a 200
        # on the tree view than a 404 on a guessed directory.
        target = f"{repo_root}/tree/main/"
    return f"s|{upstream_anchor}|{target}|g"
