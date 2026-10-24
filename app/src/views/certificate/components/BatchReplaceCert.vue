<script setup lang="ts">
import type { Cert, CertBatchReplacePreview, CertBatchReplaceReason, CertBatchReplaceSite } from '@/api/cert'
import { SwapOutlined } from '@antdv-next/icons'
import { Tag, Tooltip } from 'antdv-next'
import { computed, ref, watch } from 'vue'
import cert from '@/api/cert'

const emit = defineEmits<{
  replaced: []
}>()

const visible = ref(false)
const certOptions = ref<Cert[]>([])
const optionsLoading = ref(false)
const oldCertId = ref<number | undefined>()
const newCertId = ref<number | undefined>()

const previewLoading = ref(false)
const confirmLoading = ref(false)
const preview = ref<CertBatchReplacePreview | null>(null)
const selectedNames = ref<string[]>([])

const { message } = App.useApp()

const oldCertOptions = computed(() => certOptions.value.filter(c => c.id !== newCertId.value))
const newCertOptions = computed(() => certOptions.value.filter(c => c.id !== oldCertId.value))

const canPreview = computed(() => !!oldCertId.value && !!newCertId.value && oldCertId.value !== newCertId.value)

const selectableCount = computed(() => preview.value?.sites.filter(s => s.selectable).length ?? 0)
const selectedSites = computed(() => preview.value?.sites.filter(s => selectedNames.value.includes(s.name)) ?? [])

watch([oldCertId, newCertId], () => {
  // Certificate choice changed: the previous preview no longer matches.
  preview.value = null
  selectedNames.value = []
})

function certLabel(record: Cert) {
  const domains = record.domains?.length ? record.domains.join(', ') : record.ssl_certificate_path
  return `${record.name} — ${domains}`
}

async function loadCertOptions() {
  optionsLoading.value = true
  try {
    const all: Cert[] = []
    let page = 1
    for (;;) {
      const response = await cert.getList({ page, per_page: 100 })
      all.push(...(response.data ?? []))
      if (!response.pagination || page >= response.pagination.total_pages) {
        break
      }
      page++
    }
    certOptions.value = all
  }
  catch (error) {
    console.error(error)
    message.error($gettext('Failed to load certificates'))
  }
  finally {
    optionsLoading.value = false
  }
}

function open(initialOldCertId?: number) {
  visible.value = true
  preview.value = null
  selectedNames.value = []
  oldCertId.value = initialOldCertId
  newCertId.value = undefined
  loadCertOptions()
}

defineExpose({ open })

async function runPreview() {
  if (!canPreview.value) {
    return
  }
  previewLoading.value = true
  try {
    preview.value = await cert.batch_replace_preview({
      old_certificate_id: oldCertId.value!,
      new_certificate_id: newCertId.value!,
    })
    // Every eligible site is checked by default; the user unchecks as needed.
    selectedNames.value = preview.value.sites.filter(s => s.selectable).map(s => s.name)
  }
  catch (error) {
    console.error(error)
    preview.value = null
    selectedNames.value = []
  }
  finally {
    previewLoading.value = false
  }
}

const rowSelection = computed(() => ({
  selectedRowKeys: selectedNames.value,
  onChange: (keys: (string | number)[]) => {
    selectedNames.value = keys.map(String)
  },
  getCheckboxProps: (record: CertBatchReplaceSite) => ({
    disabled: !record.selectable,
  }),
}))

const tableColumns = computed(() => [
  { title: $gettext('Site'), dataIndex: 'name' },
  { title: $gettext('Status'), dataIndex: 'status', width: 120 },
  { title: $gettext('Affected servers'), dataIndex: 'servers', ellipsis: true },
  { title: $gettext('Eligibility'), key: 'eligibility', width: 140 },
])

function siteRowKey(record: CertBatchReplaceSite) {
  return record.name
}

function rowHasDiff(record: CertBatchReplaceSite) {
  return !!record.diff?.length
}

function filterCertOption(input: string, option?: { label?: string }) {
  return String(option?.label ?? '').toLowerCase().includes(input.toLowerCase())
}

function reasonText(reason?: CertBatchReplaceReason): string {
  if (!reason) {
    return ''
  }
  const p = reason.params ?? {}
  switch (reason.code) {
    case 'remote_deploy':
      return $gettext('The site is deployed to remote nodes only')
    case 'managed':
      return $gettext('Managed by %{by}', { by: p.by || '' })
    case 'sync_targets_configured':
      return $gettext('Synchronizes to explicitly configured cluster nodes')
    case 'site_in_maintenance':
      return $gettext('The site is in maintenance mode')
    case 'config_unparseable':
      return $gettext('The site configuration cannot be parsed')
    case 'multiple_certificate_directives':
      return $gettext('A server directly configures more than one ssl_certificate or ssl_certificate_key')
    case 'certificate_pair_mismatch':
      return $gettext('The old certificate is paired with a different private key: %{path}', { path: p.path || '' })
    case 'unsupported_reference':
      return $gettext('The certificate is referenced outside a directly configurable server block')
    case 'names_not_covered':
      return $gettext('The new certificate does not cover: %{names}', { names: p.names || '' })
    default:
      return reason.message
  }
}

function statusColor(status: string) {
  if (status === 'enabled') {
    return 'success'
  }
  if (status === 'maintenance') {
    return 'warning'
  }
  return 'default'
}

function statusLabel(status: string) {
  if (status === 'enabled') {
    return $gettext('Enabled')
  }
  if (status === 'maintenance') {
    return $gettext('Maintenance')
  }
  return $gettext('Disabled')
}

function serverSummary(record: CertBatchReplaceSite) {
  const servers = record.servers ?? []
  if (!servers.length) {
    return '-'
  }
  return servers
    .map(server => {
      const names = server.server_names.length
        ? server.server_names.join(' ')
        : $gettext('(no server_name)')
      const listen = server.listen.length ? ` [${server.listen.join(' ')}]` : ''
      return names + listen
    })
    .join('; ')
}

async function confirmReplace() {
  if (!preview.value || !selectedNames.value.length) {
    return
  }
  const sites = selectedSites.value.map(site => ({ name: site.name, content_hash: site.content_hash }))
  confirmLoading.value = true
  try {
    const result = await cert.batch_replace({
      old_certificate_id: preview.value.old_certificate_id,
      new_certificate_id: preview.value.new_certificate_id,
      new_certificate_hash: preview.value.new_certificate_hash,
      sites,
    })
    message.success($ngettext(
      'Replaced the certificate on %{count} site',
      'Replaced the certificate on %{count} sites',
      result.updated?.length ?? sites.length,
      { count: String(result.updated?.length ?? sites.length) },
    ))
    visible.value = false
    emit('replaced')
  }
  catch (error) {
    // The HTTP interceptor surfaces the backend reason (stale preview,
    // rollback cause, ...); force a fresh preview before retrying.
    console.error(error)
    selectedNames.value = []
  }
  finally {
    confirmLoading.value = false
  }
}
</script>

<template>
  <AModal
    v-model:open="visible"
    :title="$gettext('Batch Replace Certificate')"
    width="1000px"
    :ok-text="$gettext('Replace (%{count})', { count: String(selectedNames.length) })"
    :ok-button-props="{ disabled: selectedNames.length === 0 }"
    :confirm-loading="confirmLoading"
    :destroy-on-close="true"
    @ok="confirmReplace"
  >
    <ASpace direction="vertical" class="w-full" size="middle">
      <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div>
          <div class="mb-1 text-sm font-medium">
            {{ $gettext('Current certificate') }}
          </div>
          <ASelect
            v-model:value="oldCertId"
            show-search
            :loading="optionsLoading"
            :placeholder="$gettext('Select the certificate to replace')"
            :filter-option="filterCertOption"
            class="w-full"
          >
            <ASelectOption
              v-for="record in oldCertOptions"
              :key="record.id"
              :value="record.id"
              :label="certLabel(record)"
            >
              <div class="flex flex-col">
                <span>{{ record.name }}</span>
                <span class="text-xs opacity-60">
                  {{ record.domains?.join(', ') || record.ssl_certificate_path }}
                </span>
              </div>
            </ASelectOption>
          </ASelect>
        </div>
        <div>
          <div class="mb-1 text-sm font-medium">
            {{ $gettext('New certificate') }}
          </div>
          <ASelect
            v-model:value="newCertId"
            show-search
            :loading="optionsLoading"
            :placeholder="$gettext('Select the replacement certificate')"
            :filter-option="filterCertOption"
            class="w-full"
          >
            <ASelectOption
              v-for="record in newCertOptions"
              :key="record.id"
              :value="record.id"
              :label="certLabel(record)"
            >
              <div class="flex flex-col">
                <span>{{ record.name }}</span>
                <span class="text-xs opacity-60">
                  {{ record.domains?.join(', ') || record.ssl_certificate_path }}
                </span>
              </div>
            </ASelectOption>
          </ASelect>
        </div>
      </div>

      <div class="flex justify-end">
        <AButton
          type="primary"
          ghost
          :loading="previewLoading"
          :disabled="!canPreview"
          @click="runPreview"
        >
          <template #icon>
            <SwapOutlined />
          </template>
          {{ preview ? $gettext('Preview again') : $gettext('Preview') }}
        </AButton>
      </div>

      <AAlert
        v-if="preview && selectableCount === 0"
        type="warning"
        show-icon
        :message="$gettext('No eligible site directly references this certificate.')"
      />
      <AAlert
        v-else-if="preview"
        type="info"
        show-icon
        :message="$ngettext(
          '%{selectable} of %{total} site is eligible',
          '%{selectable} of %{total} sites are eligible',
          preview.sites.length,
          { selectable: String(selectableCount), total: String(preview.sites.length) },
        )"
      />

      <ATable
        v-if="preview"
        :data-source="preview.sites"
        :columns="tableColumns"
        :row-key="siteRowKey"
        :row-selection="rowSelection"
        :pagination="false"
        size="small"
        :scroll="{ y: 360 }"
        :expandable="{ rowExpandable: rowHasDiff }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.dataIndex === 'name'">
            <RouterLink
              :to="`/sites/${encodeURIComponent(record.name)}`"
              class="font-mono"
            >
              {{ record.name }}
            </RouterLink>
          </template>
          <template v-else-if="column.dataIndex === 'status'">
            <Tag :color="statusColor(record.status)">
              {{ statusLabel(record.status) }}
            </Tag>
          </template>
          <template v-else-if="column.dataIndex === 'servers'">
            <Tooltip :title="serverSummary(record)">
              <span class="block truncate font-mono">{{ serverSummary(record) }}</span>
            </Tooltip>
          </template>
          <template v-else-if="column.key === 'eligibility'">
            <Tag v-if="record.selectable" color="success">
              {{ $gettext('Eligible') }}
            </Tag>
            <Tooltip v-else :title="reasonText(record.reason)">
              <Tag color="error">
                {{ $gettext('Not eligible') }}
              </Tag>
            </Tooltip>
          </template>
        </template>
        <template #expandedRowRender="{ record }">
          <div class="cert-diff rounded border border-solid border-[var(--ant-color-border)]">
            <div
              v-for="(line, index) in record.diff"
              :key="index"
              class="cert-diff-line"
              :class="`cert-diff-${line.type}`"
            >
              <template v-if="line.type === 'spacer'">
                <span class="px-2 opacity-50">···</span>
              </template>
              <template v-else>
                <span class="cert-diff-no">{{ line.old_no || '' }}</span>
                <span class="cert-diff-no">{{ line.new_no || '' }}</span>
                <span class="cert-diff-sign">{{ line.type === 'add' ? '+' : line.type === 'remove' ? '-' : ' ' }}</span>
                <span class="cert-diff-text">{{ line.text || ' ' }}</span>
              </template>
            </div>
          </div>
        </template>
      </ATable>
    </ASpace>
  </AModal>
</template>

<style scoped>
.cert-diff {
  overflow: auto;
  max-height: 320px;
  background: var(--ant-color-fill-quaternary);
}

.cert-diff-line {
  display: flex;
  align-items: flex-start;
  font-family: var(--ant-font-family-code, monospace);
  font-size: 12px;
  line-height: 20px;
  white-space: pre;
}

.cert-diff-no {
  display: inline-block;
  width: 40px;
  flex-shrink: 0;
  padding-right: 8px;
  text-align: right;
  opacity: 0.45;
  user-select: none;
}

.cert-diff-sign {
  width: 16px;
  flex-shrink: 0;
  user-select: none;
}

.cert-diff-add {
  background: rgb(82 196 26 / 12%);
}

.cert-diff-add .cert-diff-sign {
  color: rgb(82 197 26);
}

.cert-diff-remove {
  background: rgb(255 77 79 / 12%);
}

.cert-diff-remove .cert-diff-sign {
  color: rgb(255 77 79);
}
</style>
