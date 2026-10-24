import type { AutoCertChallengeMethod } from './auto_cert'
import type { AcmeUser } from '@/api/acme_user'
import type { ModelBase } from '@/api/curd'
import type { DnsCredential } from '@/api/dns_credential'
import type { ConfigStatus, PrivateKeyType } from '@/constants'
import { extendCurdApi, http, useCurdApi } from '@uozi-admin/request'
import { normalizePrivateKeyType, PrivateKeyTypeEnum } from '@/constants'

export const CertStatus = {
  Pending: 'pending',
  Success: 'success',
  Failure: 'failure',
} as const

export type CertStatusType = '' | typeof CertStatus[keyof typeof CertStatus]

export interface SelfSignedCertConfig {
  ip_addresses: string[]
  validity_days: number
}

export interface Cert extends ModelBase {
  name: string
  domains: string[]
  filename: string
  ssl_certificate_path: string
  ssl_certificate: string
  ssl_certificate_key_path: string
  ssl_certificate_key: string
  auto_cert: number
  challenge_method: keyof typeof AutoCertChallengeMethod
  profile: string
  dns_credential_id: number
  dns_credential?: DnsCredential
  acme_user_id: number
  acme_user?: AcmeUser
  key_type: string
  log: string
  certificate_info: CertificateInfo
  deployment_status: CertificateDeploymentStatus
  used_by?: CertificateUsage[]
  sync_node_ids: number[]
  must_staple: boolean
  lego_disable_cname_support: boolean
  disable_authoritative_ns_propagation: boolean
  enable_common_name: boolean
  revoke_old: boolean
  status: CertStatusType
  last_error: string
  last_attempt_at: string | null
  self_signed_config?: SelfSignedCertConfig
}

export interface CertificateDeploymentStatus {
  state: 'not_applicable' | 'consistent' | 'legacy_drift' | 'mismatch' | 'unreadable'
  site_name?: string
  managed_certificate_path?: string
  managed_certificate_key_path?: string
  configured_certificate_paths?: string[]
  configured_certificate_key_paths?: string[]
  automatic_migration_available: boolean
  error?: string
}

/** A site or stream whose configuration loads the certificate. */
export interface CertificateUsage {
  kind: 'site' | 'stream'
  name: string
  status: ConfigStatus
}

export interface ImportExistingCertPayload {
  name?: string
  ssl_certificate_path?: string
  ssl_certificate_key_path?: string
  key_type?: string
}

export interface DiscoveredCertificatePair {
  name?: string
  dir?: string
  ssl_certificate_path: string
  ssl_certificate_key_path: string
  fingerprint: string
  key_type: string
  certificate_info?: CertificateInfo
}

export interface DiscoverNewCertsPayload {
  new_only?: boolean
}

export interface DiscoverNewCertsResponse {
  candidates: DiscoveredCertificatePair[]
}

export interface CertificateInfo {
  subject_name: string
  issuer_name: string
  not_after: string
  not_before: string
  subject_alt_names?: string[]
}

export interface CertificateResult {
  ssl_certificate: string
  ssl_certificate_key: string
  key_type: PrivateKeyType
  profile?: string
}

export interface SelfSignedCertPayload {
  name: string
  domains: string[]
  ip_addresses: string[]
  key_type: string
  validity_days: number
  sync_node_ids?: number[]
}

export type CertificateFileFormat = 'crt' | 'key' | 'pfx'

export interface CertificateDownloadPayload {
  format: CertificateFileFormat | 'zip'
  // Files to pack when format is zip
  formats?: CertificateFileFormat[]
  pfx_password?: string
}

export interface CertificateArchive {
  name: string
  ssl_certificate: string
  ssl_certificate_key: string
  certificate_file_name: string
  private_key_file_name: string
  chain_completed_from_zip: boolean
}

// toSelfSignedPayload maps a persisted Cert to an editable self-signed payload.
export function toSelfSignedPayload(c: Cert): SelfSignedCertPayload {
  const domains = c.domains?.length ? [...c.domains] : ['']
  const ipAddresses = c.self_signed_config?.ip_addresses?.length
    ? [...c.self_signed_config.ip_addresses]
    : ['']
  // Backend stores key_type in its canonical form (EC256, RSA2048…); the
  // form ASelect expects the legacy keys (P256, 2048…). Normalize so the
  // option highlights correctly when editing an existing self-signed cert.
  const keyType = normalizePrivateKeyType(c.key_type) || PrivateKeyTypeEnum.P256
  return {
    name: c.name ?? '',
    domains,
    ip_addresses: ipAddresses,
    key_type: keyType,
    validity_days: c.self_signed_config?.validity_days || 365,
    sync_node_ids: [...(c.sync_node_ids ?? [])],
  }
}

export interface RecommendCertResponse {
  certificate: Cert | null
}

/** Why a site cannot be selected in a batch certificate replacement. */
export interface CertBatchReplaceReason {
  code:
    | 'remote_deploy'
    | 'managed'
    | 'sync_targets_configured'
    | 'site_in_maintenance'
    | 'config_unparseable'
    | 'multiple_certificate_directives'
    | 'certificate_pair_mismatch'
    | 'unsupported_reference'
    | 'names_not_covered'
    | 'site_unavailable'
  message: string
  params?: Record<string, string>
}

export interface CertBatchReplaceServer {
  index: number
  listen: string[]
  server_names: string[]
}

export interface CertBatchReplaceDiffLine {
  type: 'context' | 'remove' | 'add' | 'spacer'
  text: string
  old_no?: number
  new_no?: number
}

export interface CertBatchReplaceSite {
  name: string
  status: ConfigStatus
  selectable: boolean
  reason?: CertBatchReplaceReason
  servers?: CertBatchReplaceServer[]
  diff?: CertBatchReplaceDiffLine[]
  content_hash: string
}

export interface CertBatchReplacePreview {
  old_certificate_id: number
  new_certificate_id: number
  old_certificate_path: string
  old_certificate_key_path: string
  new_certificate_path: string
  new_certificate_key_path: string
  new_not_before: string
  new_not_after: string
  new_certificate_hash: string
  sites: CertBatchReplaceSite[]
}

export interface CertBatchReplacePayload {
  old_certificate_id: number
  new_certificate_id: number
  new_certificate_hash: string
  sites: { name: string, content_hash: string }[]
}

export interface CertBatchReplaceResult {
  updated: string[]
}

const cert = extendCurdApi(useCurdApi<Cert>('/certs'), {
  import_existing(payload: ImportExistingCertPayload): Promise<Cert> {
    return http.post('/cert_import', payload)
  },
  discover_new(payload: DiscoverNewCertsPayload): Promise<DiscoverNewCertsResponse> {
    return http.post('/cert_discover_new', payload)
  },
  generate_self_signed(payload: SelfSignedCertPayload): Promise<Cert> {
    return http.post('/self_signed_cert', payload)
  },
  modify_self_signed(id: number, payload: SelfSignedCertPayload): Promise<Cert> {
    return http.post(`/self_signed_cert/${id}`, payload)
  },
  download_file(id: number, payload: CertificateDownloadPayload): Promise<Blob> {
    return http.post(`/certs/${id}/download`, payload, { responseType: 'blob' })
  },
  // Picks the certificate that covers every domain best; null when none does.
  recommend(domains: string[]): Promise<RecommendCertResponse> {
    return http.post('/cert_recommendation', { domains })
  },
  parse_archive(file: File): Promise<CertificateArchive> {
    const formData = new FormData()
    formData.append('file', file)
    return http.post('/cert_parse_archive', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  batch_replace_preview(payload: {
    old_certificate_id: number
    new_certificate_id: number
  }): Promise<CertBatchReplacePreview> {
    return http.post('/cert_batch_replace/preview', payload)
  },
  batch_replace(payload: CertBatchReplacePayload): Promise<CertBatchReplaceResult> {
    return http.post('/cert_batch_replace', payload)
  },
})

export default cert
