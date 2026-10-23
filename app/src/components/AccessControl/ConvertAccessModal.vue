<script setup lang="ts">
import type { AccessServerState } from '@/api/access_list'
import type { AccessConversionPreview, AccessDiffLine, Site } from '@/api/site'
import accessList from '@/api/access_list'
import siteApi from '@/api/site'
import { translateError } from '@/lib/http/error'
import { normalizeHttpError } from '@/lib/http/normalizeError'

interface BlockOption {
  value: string
  label: string
  disabled?: boolean
}

const props = defineProps<{
  site: Site | null
}>()

const emit = defineEmits<{
  done: []
}>()

const open = defineModel<boolean>('open', { default: false })

const { message } = App.useApp()

const isLoadingBlocks = ref(false)
const blockError = ref('')
const servers = ref<AccessServerState[]>([])

const selectedBlock = ref<string>()
const listName = ref('')
const listSlug = ref('')
const isSlugTouched = ref(false)

const isPreviewing = ref(false)
const isCommitting = ref(false)
const previewError = ref('')
const preview = ref<AccessConversionPreview | null>(null)

function slugify(name: string) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63)
}

watch(listName, name => {
  if (!isSlugTouched.value)
    listSlug.value = slugify(name)
})

// Any input change after a preview invalidates it.
watch([selectedBlock, listName, listSlug], () => {
  preview.value = null
  previewError.value = ''
})

function parseBlock(value?: string): { server: number, location?: number } | undefined {
  if (!value)
    return undefined
  const [server, location] = value.split(':')
  const block = { server: Number(server) }
  if (location !== undefined)
    return { ...block, location: Number(location) }
  return block
}

const blockOptions = computed<BlockOption[]>(() => {
  const options: BlockOption[] = []
  servers.value.forEach((server, i) => {
    options.push({
      value: String(i),
      label: server.server_name
        ? `${$gettext('Server')} ${i + 1} · ${server.server_name}`
        : `${$gettext('Server')} ${i + 1}`,
      disabled: server.mode !== 'manual',
    })
    server.locations.forEach((location, j) => {
      options.push({
        value: `${i}:${j}`,
        label: `    ${$gettext('Location')} ${location.path || '/'}`,
        disabled: location.mode !== 'manual',
      })
    })
  })
  return options
})

const hasManualBlock = computed(() => blockOptions.value.some(option => !option.disabled))
const canPreview = computed(() => !!parseBlock(selectedBlock.value) && listName.value.trim() !== '' && listSlug.value.trim() !== '')

function resetForm() {
  servers.value = []
  selectedBlock.value = undefined
  listName.value = ''
  listSlug.value = ''
  isSlugTouched.value = false
  preview.value = null
  previewError.value = ''
  blockError.value = ''
}

watch(open, async value => {
  if (!value || !props.site)
    return
  resetForm()
  isLoadingBlocks.value = true
  try {
    const detail = await siteApi.getItem(props.site.name, undefined, { skipErrHandling: true })
    const state = await accessList.getState({ content: detail.config })
    servers.value = state.servers ?? []
    if (!hasManualBlock.value)
      blockError.value = $gettext('No server or direct location of this site contains manual allow or deny rules.')
  }
  catch (error) {
    blockError.value = await translateError(normalizeHttpError(error))
  }
  finally {
    isLoadingBlocks.value = false
  }
})

async function runPreview() {
  const target = parseBlock(selectedBlock.value)
  if (!target || !props.site)
    return
  isPreviewing.value = true
  previewError.value = ''
  try {
    preview.value = await siteApi.previewAccessConversion(props.site.name, {
      server: target.server,
      location: target.location,
      name: listName.value.trim(),
      slug: listSlug.value.trim(),
    })
  }
  catch (error) {
    preview.value = null
    previewError.value = await translateError(normalizeHttpError(error))
  }
  finally {
    isPreviewing.value = false
  }
}

interface RuleRow {
  key: number
  type: string
  value: string
  note?: string
}

const ruleColumns = [
  { title: $gettext('Type'), dataIndex: 'type', width: 90 },
  { title: $gettext('Value'), dataIndex: 'value' },
  { title: $gettext('Note'), dataIndex: 'note' },
]

const ruleRows = computed<RuleRow[]>(() =>
  (preview.value?.rules ?? []).map((rule, i) => ({
    key: i,
    type: rule.type,
    value: rule.value ?? '',
    note: rule.note,
  })),
)

function diffLineClass(line: AccessDiffLine) {
  switch (line.kind) {
    case 'add':
      return 'block bg-green-500/10 text-green-700 dark:text-green-400'
    case 'remove':
      return 'block bg-red-500/10 text-red-700 dark:text-red-400'
    case 'hunk':
      return 'block text-gray-400 dark:text-gray-500 select-none'
    default:
      return 'block text-gray-700 dark:text-gray-300'
  }
}

function diffMarker(line: AccessDiffLine) {
  switch (line.kind) {
    case 'add':
      return '+'
    case 'remove':
      return '-'
    case 'hunk':
      return ''
    default:
      return ' '
  }
}

async function commit() {
  if (!props.site || !preview.value)
    return
  isCommitting.value = true
  try {
    await siteApi.commitAccessConversion(props.site.name, {
      server: preview.value.server,
      location: preview.value.location,
      name: preview.value.name,
      slug: preview.value.slug,
      token: preview.value.token,
    })
    message.success($gettext('Access list "%{name}" created and the site now includes it.', { name: preview.value.name }))
    open.value = false
    emit('done')
  }
  catch (error) {
    const cosyError = normalizeHttpError(error)
    previewError.value = await translateError(cosyError)
    if (cosyError.code === 40024)
      preview.value = null
  }
  finally {
    isCommitting.value = false
  }
}
</script>

<template>
  <AModal
    v-model:open="open"
    :title="$gettext('Convert allow/deny rules to an access list')"
    :ok-text="$gettext('Convert')"
    :cancel-text="$gettext('Cancel')"
    :ok-button-props="{ disabled: !preview, loading: isCommitting }"
    destroy-on-hidden
    width="780px"
    data-testid="convert-access-modal"
    @ok="commit"
  >
    <AFlex vertical gap="middle">
      <p class="mb-0 text-gray-500 dark:text-gray-400">
        {{ $gettext('Choose a server block or one of its direct locations. Its allow and deny rules become a new access list and are replaced by a single include directive. Requests that no rule matches still pass.') }}
      </p>

      <ASelect
        v-model:value="selectedBlock"
        :options="blockOptions"
        :loading="isLoadingBlocks"
        :placeholder="$gettext('Select a server or a direct location')"
        :disabled="isLoadingBlocks || servers.length === 0"
        show-search
        data-testid="convert-block-select"
      />

      <AAlert
        v-if="blockError"
        type="warning"
        show-icon
        :message="blockError"
      />

      <AFormItem :label="$gettext('Access list name')" required>
        <AInput
          v-model:value="listName"
          :placeholder="$gettext('For example: Office access')"
          :maxlength="100"
          data-testid="convert-list-name"
        />
      </AFormItem>
      <AFormItem :label="$gettext('Identifier')" required>
        <AInput
          v-model:value="listSlug"
          placeholder="office-access"
          data-testid="convert-list-slug"
          @input="isSlugTouched = true"
        >
          <template #addonAfter>
            .conf
          </template>
        </AInput>
      </AFormItem>

      <div>
        <AButton
          type="primary"
          ghost
          :loading="isPreviewing"
          :disabled="!canPreview"
          data-testid="convert-preview-button"
          @click="runPreview"
        >
          {{ $gettext('Preview conversion') }}
        </AButton>
      </div>

      <AAlert
        v-if="previewError"
        type="error"
        show-icon
        :message="previewError"
      />

      <template v-if="preview">
        <ADivider class="!my-1">
          {{ preview.location_path
            ? `${$gettext('Location')} ${preview.location_path}`
            : `${$gettext('Server')}${preview.server_name ? ` · ${preview.server_name}` : ''}` }}
        </ADivider>

        <AFlex justify="space-between" align="center">
          <span class="font-medium">
            {{ $gettext('Extracted rules (%{count})', { count: String(preview.rules.length) }) }}
          </span>
          <ATag color="blue">
            {{ $gettext('Unmatched requests are allowed') }}
          </ATag>
        </AFlex>

        <ATable
          :data-source="ruleRows"
          :columns="ruleColumns"
          :pagination="false"
          size="small"
          :scroll="{ y: 200 }"
        >
          <template #bodyCell="{ column, record }">
            <ATag
              v-if="column.dataIndex === 'type'"
              :color="record.type === 'allow' ? 'green' : 'red'"
            >
              {{ record.type }}
            </ATag>
            <span v-else-if="column.dataIndex === 'value'">
              {{ record.value }}
            </span>
            <span v-else>
              {{ record.note }}
            </span>
          </template>
        </ATable>

        <div>
          <div class="mb-1 font-medium">
            {{ $gettext('Configuration changes') }}
          </div>
          <pre
            class="m-0 max-h-72 overflow-auto rounded bg-gray-50 p-3 text-xs leading-5 dark:bg-gray-900"
            data-testid="convert-diff"
          ><span
            v-for="(line, i) in preview.diff"
            :key="i"
            :class="diffLineClass(line)"
          >{{ diffMarker(line) }}{{ line.text === '' ? ' ' : line.text }}
</span></pre>
        </div>
      </template>
    </AFlex>
  </AModal>
</template>
