export interface OutputReplaceRule {
  pattern: string;
  with: string;
  flags?: string;
}

export interface OutputFilter {
  trim?: boolean;
  dropEmpty?: boolean;
  include?: string;
  exclude?: string;
  caseInsensitive?: boolean;
  regex?: string;
  regexGroup?: number;
  regexAll?: boolean;
  replace?: OutputReplaceRule[];
  columns?: number[];
  delimiter?: string;
  columnJoin?: string;
  sort?: boolean;
  unique?: boolean;
  head?: number;
  tail?: number;
  prefix?: string;
  suffix?: string;
  joinWith?: string;
}

export type ConditionOperator =
  | 'equals'
  | '=='
  | 'notEquals'
  | '!='
  | 'contains'
  | 'notContains'
  | 'startsWith'
  | 'endsWith'
  | 'matches'
  | 'notMatches'
  | 'isEmpty'
  | 'isNotEmpty'
  | 'gt'
  | '>'
  | 'gte'
  | '>='
  | 'lt'
  | '<'
  | 'lte'
  | '<=';

export interface WorkflowConditionLeaf {
  from?: string;
  field?: 'stdout' | 'rawStdout' | 'stderr' | 'exitCode' | 'ok' | 'linesCount';
  op: ConditionOperator;
  value?: string | number | boolean;
  caseInsensitive?: boolean;
}

export interface WorkflowConditionCompound {
  all?: WorkflowCondition[];
  any?: WorkflowCondition[];
  not?: WorkflowCondition;
}

export type WorkflowCondition = WorkflowConditionLeaf | WorkflowConditionCompound;

export interface WorkflowRunStep {
  type: 'run';
  id?: string;
  saveAs?: string;
  command: string;
  continueOnError?: boolean;
  sleepAfterSec?: number;
  silent?: boolean;
  filter?: OutputFilter;
}

export interface WorkflowSleepStep {
  type: 'sleep';
  seconds: number;
}

export interface WorkflowIfStep {
  type: 'if';
  when: WorkflowCondition;
  then: WorkflowStep[];
  else?: WorkflowStep[];
}

export interface WorkflowSetStep {
  type: 'set';
  name: string;
  value: string;
  filter?: OutputFilter;
}

export interface WorkflowLogStep {
  type: 'log';
  message: string;
}

export interface WorkflowStopStep {
  type: 'stop' | 'fail';
  exitCode?: number;
  message?: string;
}

export interface WorkflowLoopStep {
  type: 'loop';
  id?: string;
  maxIterations: number;
  intervalSec?: number;
  steps: WorkflowStep[];
  until?: WorkflowCondition;
  onTimeout?: 'fail' | 'continue';
  timeoutMessage?: string;
}

export type WorkflowStep =
  | WorkflowRunStep
  | WorkflowSleepStep
  | WorkflowIfStep
  | WorkflowLoopStep
  | WorkflowSetStep
  | WorkflowLogStep
  | WorkflowStopStep;

export interface WorkflowTableRow {
  label: string;
  value: string;
}

export interface WorkflowOutputConfig {
  format?: 'text' | 'template' | 'table' | 'json' | 'lines';
  template?: string;
  lines?: string[];
  source?: string;
  headers?: string[];
  columns?: number[];
  delimiter?: string;
  rows?: WorkflowTableRow[];
  fields?: Record<string, string | number | boolean>;
  autoType?: boolean;
  filter?: OutputFilter;
  joinWith?: string;
}

export type WorkflowInputType = 'text' | 'password' | 'select' | 'number' | 'boolean';

export interface WorkflowInputDef {
  name: string;
  label?: string;
  type?: WorkflowInputType;
  options?: string[];
  default?: string | number | boolean;
  placeholder?: string;
  description?: string;
  required?: boolean;
  secret?: boolean;
}

export interface WorkflowDefinition {
  stopOnError?: boolean;
  inputs?: WorkflowInputDef[];
  vars?: Record<string, string | number | boolean>;
  steps: WorkflowStep[];
  output?: WorkflowOutputConfig;
}

export interface WorkflowSummary {
  stepCount: number;
  runCount: number;
  conditionCount: number;
  totalSleepSec: number;
  inputCount: number;
  outputFormat: string;
  previewLine: string;
}

export type WorkflowValidationResult =
  | {
      ok: true;
      workflow: WorkflowDefinition;
      normalizedJson: string;
      summary: WorkflowSummary;
    }
  | {
      ok: false;
      error: string;
    };

export interface WorkflowStepRecord {
  id: string;
  command: string;
  exitCode: number;
  ok: boolean;
  stdout: string;
  rawStdout: string;
  stderr: string;
  linesCount: number;
  silent: boolean;
}

export interface WorkflowTargetInfo {
  ip: string;
  port: number;
  user: string;
  label: string;
}

export interface WorkflowContext {
  target: WorkflowTargetInfo;
  vars: Record<string, string>;
  steps: Record<string, WorkflowStepRecord>;
  stepOrder: WorkflowStepRecord[];
  last: WorkflowStepRecord | null;
  logs: string[];
  stderrParts: string[];
  executedCount: number;
  stopped: boolean;
  finalExitCode: number;
}

export interface WorkflowExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  executedSteps: number;
  commandsRun: string[];
}

const VALID_OPS = new Set<string>([
  'equals',
  '==',
  'notEquals',
  '!=',
  'contains',
  'notContains',
  'startsWith',
  'endsWith',
  'matches',
  'notMatches',
  'isEmpty',
  'isNotEmpty',
  'gt',
  '>',
  'gte',
  '>=',
  'lt',
  '<',
  'lte',
  '<=',
]);

const VALID_FIELDS = new Set<string>(['stdout', 'rawStdout', 'stderr', 'exitCode', 'ok', 'linesCount']);
const VALID_FORMATS = new Set<string>(['text', 'template', 'table', 'json', 'lines']);
const VALID_INPUT_TYPES = new Set<string>(['text', 'password', 'select', 'number', 'boolean']);
const VALID_IDENT_RE = /^[a-zA-Z_][a-zA-Z0-9_-]{0,47}$/;
const MAX_DEPTH = 10;
const MAX_DEFINED_STEPS = 100;
const MAX_EXECUTED_STEPS = 300;
const MAX_INPUTS = 30;
const MAX_RUNTIME_VARS = 50;
const MAX_VAR_VALUE_LEN = 2000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateRegex(pattern: string, flags: string | undefined, pathLabel: string): string | null {
  try {
    new RegExp(pattern, flags || '');
    return null;
  } catch (err) {
    return `${pathLabel}: Ungültiger Regex "${pattern}" (${err instanceof Error ? err.message : 'Syntaxfehler'}).`;
  }
}

function validateFilter(raw: unknown, pathLabel: string): { filter?: OutputFilter; error?: string } {
  if (raw === undefined || raw === null) return {};
  if (!isRecord(raw)) {
    return { error: `${pathLabel}: filter muss ein JSON-Objekt sein.` };
  }
  const f: OutputFilter = {};
  if (raw.trim !== undefined) f.trim = Boolean(raw.trim);
  if (raw.dropEmpty !== undefined) f.dropEmpty = Boolean(raw.dropEmpty);
  if (raw.caseInsensitive !== undefined) f.caseInsensitive = Boolean(raw.caseInsensitive);
  if (raw.sort !== undefined) f.sort = Boolean(raw.sort);
  if (raw.unique !== undefined) f.unique = Boolean(raw.unique);

  const ciFlags = f.caseInsensitive ? 'i' : '';

  if (typeof raw.include === 'string' && raw.include.length > 0) {
    const err = validateRegex(raw.include, ciFlags, `${pathLabel}.include`);
    if (err) return { error: err };
    f.include = raw.include;
  }
  if (typeof raw.exclude === 'string' && raw.exclude.length > 0) {
    const err = validateRegex(raw.exclude, ciFlags, `${pathLabel}.exclude`);
    if (err) return { error: err };
    f.exclude = raw.exclude;
  }
  if (typeof raw.regex === 'string' && raw.regex.length > 0) {
    const err = validateRegex(raw.regex, ciFlags, `${pathLabel}.regex`);
    if (err) return { error: err };
    f.regex = raw.regex;
  }
  if (raw.regexGroup !== undefined) {
    const n = Math.floor(Number(raw.regexGroup));
    if (!Number.isFinite(n) || n < 0 || n > 20) {
      return { error: `${pathLabel}.regexGroup muss eine Zahl zwischen 0 und 20 sein.` };
    }
    f.regexGroup = n;
  }
  if (raw.regexAll !== undefined) f.regexAll = Boolean(raw.regexAll);

  if (raw.replace !== undefined) {
    if (!Array.isArray(raw.replace)) {
      return { error: `${pathLabel}.replace muss ein Array sein.` };
    }
    const rules: OutputReplaceRule[] = [];
    for (let i = 0; i < raw.replace.length; i++) {
      const r = raw.replace[i];
      if (!isRecord(r) || typeof r.pattern !== 'string' || r.pattern.length === 0) {
        return { error: `${pathLabel}.replace[${i}]: pattern (String) ist erforderlich.` };
      }
      const flags = typeof r.flags === 'string' ? r.flags.replace(/[^gimsu]/g, '') : 'g';
      const err = validateRegex(r.pattern, flags, `${pathLabel}.replace[${i}]`);
      if (err) return { error: err };
      rules.push({
        pattern: r.pattern,
        with: typeof r.with === 'string' ? r.with : String(r.with ?? ''),
        flags,
      });
    }
    f.replace = rules;
  }

  if (raw.columns !== undefined) {
    if (!Array.isArray(raw.columns)) {
      return { error: `${pathLabel}.columns muss ein Zahlen-Array (1-basiert) sein.` };
    }
    const cols: number[] = [];
    for (const c of raw.columns) {
      const n = Math.floor(Number(c));
      if (!Number.isFinite(n) || n < 1 || n > 100) {
        return { error: `${pathLabel}.columns enthält ungültige Spaltennummer "${String(c)}" (1..100).` };
      }
      cols.push(n);
    }
    f.columns = cols;
  }
  if (typeof raw.delimiter === 'string' && raw.delimiter.length > 0) {
    const err = validateRegex(raw.delimiter, '', `${pathLabel}.delimiter`);
    if (err) return { error: err };
    f.delimiter = raw.delimiter;
  }
  if (typeof raw.columnJoin === 'string') f.columnJoin = raw.columnJoin;
  if (raw.head !== undefined) {
    const n = Math.floor(Number(raw.head));
    if (!Number.isFinite(n) || n < 1) {
      return { error: `${pathLabel}.head muss >= 1 sein.` };
    }
    f.head = n;
  }
  if (raw.tail !== undefined) {
    const n = Math.floor(Number(raw.tail));
    if (!Number.isFinite(n) || n < 1) {
      return { error: `${pathLabel}.tail muss >= 1 sein.` };
    }
    f.tail = n;
  }
  if (typeof raw.prefix === 'string') f.prefix = raw.prefix;
  if (typeof raw.suffix === 'string') f.suffix = raw.suffix;
  if (typeof raw.joinWith === 'string') f.joinWith = raw.joinWith;

  return { filter: f };
}

function validateCondition(
  raw: unknown,
  pathLabel: string,
  depth: number
): { condition?: WorkflowCondition; error?: string } {
  if (depth > MAX_DEPTH) {
    return { error: `${pathLabel}: Maximale Verschachtelungstiefe (${MAX_DEPTH}) überschritten.` };
  }
  if (!isRecord(raw)) {
    return { error: `${pathLabel}: Bedingung (when) muss ein JSON-Objekt sein.` };
  }

  if (raw.all !== undefined || raw.any !== undefined || raw.not !== undefined) {
    const comp: WorkflowConditionCompound = {};
    if (raw.all !== undefined) {
      if (!Array.isArray(raw.all) || raw.all.length === 0) {
        return { error: `${pathLabel}.all muss ein nicht-leeres Array sein.` };
      }
      comp.all = [];
      for (let i = 0; i < raw.all.length; i++) {
        const res = validateCondition(raw.all[i], `${pathLabel}.all[${i}]`, depth + 1);
        if (res.error) return { error: res.error };
        comp.all.push(res.condition!);
      }
    }
    if (raw.any !== undefined) {
      if (!Array.isArray(raw.any) || raw.any.length === 0) {
        return { error: `${pathLabel}.any muss ein nicht-leeres Array sein.` };
      }
      comp.any = [];
      for (let i = 0; i < raw.any.length; i++) {
        const res = validateCondition(raw.any[i], `${pathLabel}.any[${i}]`, depth + 1);
        if (res.error) return { error: res.error };
        comp.any.push(res.condition!);
      }
    }
    if (raw.not !== undefined) {
      const res = validateCondition(raw.not, `${pathLabel}.not`, depth + 1);
      if (res.error) return { error: res.error };
      comp.not = res.condition!;
    }
    return { condition: comp };
  }

  const op = typeof raw.op === 'string' ? raw.op.trim() : '';
  if (!VALID_OPS.has(op)) {
    return {
      error: `${pathLabel}.op: Unbekannter Operator "${op}". Erlaubt: equals, notEquals, contains, notContains, startsWith, endsWith, matches, notMatches, isEmpty, isNotEmpty, gt, gte, lt, lte.`,
    };
  }
  const field = typeof raw.field === 'string' ? raw.field.trim() : 'stdout';
  if (!VALID_FIELDS.has(field)) {
    return {
      error: `${pathLabel}.field: Ungültiges Feld "${field}". Erlaubt: stdout, rawStdout, stderr, exitCode, ok, linesCount.`,
    };
  }

  if ((op === 'matches' || op === 'notMatches') && typeof raw.value === 'string') {
    const err = validateRegex(raw.value, raw.caseInsensitive ? 'i' : '', `${pathLabel}.value`);
    if (err) return { error: err };
  }

  const leaf: WorkflowConditionLeaf = {
    ...(typeof raw.from === 'string' && raw.from.trim() ? { from: raw.from.trim() } : {}),
    field: field as WorkflowConditionLeaf['field'],
    op: op as ConditionOperator,
    ...(raw.value !== undefined && raw.value !== null
      ? {
          value:
            typeof raw.value === 'string' || typeof raw.value === 'number' || typeof raw.value === 'boolean'
              ? raw.value
              : String(raw.value),
        }
      : {}),
    ...(raw.caseInsensitive !== undefined ? { caseInsensitive: Boolean(raw.caseInsensitive) } : {}),
  };
  return { condition: leaf };
}

interface ValidationCounters {
  stepCount: number;
  runCount: number;
  conditionCount: number;
  totalSleepSec: number;
}

function validateSteps(
  rawSteps: unknown,
  pathLabel: string,
  depth: number,
  counters: ValidationCounters
): { steps?: WorkflowStep[]; error?: string } {
  if (depth > MAX_DEPTH) {
    return { error: `${pathLabel}: Maximale Verschachtelungstiefe (${MAX_DEPTH}) überschritten.` };
  }
  if (!Array.isArray(rawSteps)) {
    return { error: `${pathLabel} muss ein JSON-Array aus Schritten sein.` };
  }

  const result: WorkflowStep[] = [];
  for (let i = 0; i < rawSteps.length; i++) {
    const item = rawSteps[i];
    const p = `${pathLabel}[${i}]`;
    counters.stepCount++;
    if (counters.stepCount > MAX_DEFINED_STEPS) {
      return { error: `Workflow darf maximal ${MAX_DEFINED_STEPS} Schritte enthalten.` };
    }
    if (!isRecord(item)) {
      return { error: `${p}: Jeder Schritt muss ein JSON-Objekt sein.` };
    }
    const stepType = typeof item.type === 'string' ? item.type.trim() : '';

    if (stepType === 'run') {
      const cmd = typeof item.command === 'string' ? item.command.trim() : '';
      if (!cmd) {
        return { error: `${p}: "run"-Schritt benötigt ein nicht-leeres "command"-Feld.` };
      }
      const idRaw = typeof item.id === 'string' ? item.id.trim() : typeof item.saveAs === 'string' ? item.saveAs.trim() : '';
      if (idRaw && !/^[a-zA-Z_][a-zA-Z0-9_-]{0,47}$/.test(idRaw)) {
        return { error: `${p}.id: Ungültige Schritt-ID "${idRaw}" (erlaubt: Buchstaben, Ziffern, _, -).` };
      }
      const sleepAfterSec =
        item.sleepAfterSec !== undefined
          ? Math.min(600, Math.max(0, Math.floor(Number(item.sleepAfterSec) || 0)))
          : 0;
      const filterRes = validateFilter(item.filter, `${p}.filter`);
      if (filterRes.error) return { error: filterRes.error };

      counters.runCount++;
      counters.totalSleepSec += sleepAfterSec;

      result.push({
        type: 'run',
        ...(idRaw ? { id: idRaw } : {}),
        command: cmd,
        ...(item.continueOnError !== undefined ? { continueOnError: Boolean(item.continueOnError) } : {}),
        ...(sleepAfterSec > 0 ? { sleepAfterSec } : {}),
        ...(item.silent !== undefined ? { silent: Boolean(item.silent) } : {}),
        ...(filterRes.filter ? { filter: filterRes.filter } : {}),
      });
    } else if (stepType === 'sleep') {
      const sec = Math.floor(Number(item.seconds));
      if (!Number.isFinite(sec) || sec < 0 || sec > 600) {
        return { error: `${p}.seconds: Muss eine Zahl zwischen 0 und 600 sein.` };
      }
      counters.totalSleepSec += sec;
      result.push({ type: 'sleep', seconds: sec });
    } else if (stepType === 'if') {
      const condRes = validateCondition(item.when, `${p}.when`, depth + 1);
      if (condRes.error) return { error: condRes.error };
      if (!Array.isArray(item.then) || item.then.length === 0) {
        return { error: `${p}.then: Ein "if"-Schritt benötigt mindestens einen Schritt in "then".` };
      }
      const thenRes = validateSteps(item.then, `${p}.then`, depth + 1, counters);
      if (thenRes.error) return { error: thenRes.error };

      let elseSteps: WorkflowStep[] | undefined;
      if (item.else !== undefined && item.else !== null) {
        const elseRes = validateSteps(item.else, `${p}.else`, depth + 1, counters);
        if (elseRes.error) return { error: elseRes.error };
        elseSteps = elseRes.steps;
      }

      counters.conditionCount++;
      result.push({
        type: 'if',
        when: condRes.condition!,
        then: thenRes.steps!,
        ...(elseSteps && elseSteps.length > 0 ? { else: elseSteps } : {}),
      });
    } else if (stepType === 'set') {
      const name = typeof item.name === 'string' ? item.name.trim() : '';
      if (!/^[a-zA-Z_][a-zA-Z0-9_-]{0,47}$/.test(name)) {
        return { error: `${p}.name: Ungültiger Variablenname "${name}".` };
      }
      const value = item.value !== undefined && item.value !== null ? String(item.value) : '';
      const filterRes = validateFilter(item.filter, `${p}.filter`);
      if (filterRes.error) return { error: filterRes.error };
      result.push({
        type: 'set',
        name,
        value,
        ...(filterRes.filter ? { filter: filterRes.filter } : {}),
      });
    } else if (stepType === 'log') {
      const message = item.message !== undefined && item.message !== null ? String(item.message) : '';
      result.push({ type: 'log', message });
    } else if (stepType === 'stop' || stepType === 'fail') {
      const defaultCode = stepType === 'fail' ? 1 : 0;
      const exitCode =
        item.exitCode !== undefined ? Math.min(255, Math.max(0, Math.floor(Number(item.exitCode) || 0))) : defaultCode;
      const message = typeof item.message === 'string' ? item.message : undefined;
      result.push({
        type: stepType,
        exitCode,
        ...(message !== undefined ? { message } : {}),
      });
    } else if (stepType === 'loop') {
      const idRaw = typeof item.id === 'string' ? item.id.trim() : '';
      if (idRaw && !/^[a-zA-Z_][a-zA-Z0-9_-]{0,47}$/.test(idRaw)) {
        return {
          error: `${p}.id: Ungültige Schritt-ID "${idRaw}" (erlaubt: Buchstaben, Ziffern, _, -).`,
        };
      }
      const maxIter =
        item.maxIterations !== undefined ? Math.floor(Number(item.maxIterations)) : 10;
      if (!Number.isFinite(maxIter) || maxIter < 1 || maxIter > 120) {
        return { error: `${p}.maxIterations: Muss eine Zahl zwischen 1 und 120 sein.` };
      }
      const intervalSec =
        item.intervalSec !== undefined ? Math.floor(Number(item.intervalSec)) : 0;
      if (!Number.isFinite(intervalSec) || intervalSec < 0 || intervalSec > 600) {
        return { error: `${p}.intervalSec: Muss eine Zahl zwischen 0 und 600 sein.` };
      }
      if (!Array.isArray(item.steps) || item.steps.length === 0) {
        return { error: `${p}.steps: Ein "loop"-Schritt benötigt mindestens einen Schritt in "steps".` };
      }
      const bodyRes = validateSteps(item.steps, `${p}.steps`, depth + 1, counters);
      if (bodyRes.error) return { error: bodyRes.error };

      let untilCond: WorkflowCondition | undefined;
      if (item.until !== undefined && item.until !== null) {
        const untilRes = validateCondition(item.until, `${p}.until`, depth + 1);
        if (untilRes.error) return { error: untilRes.error };
        untilCond = untilRes.condition;
        counters.conditionCount++;
      }

      const onTimeout = item.onTimeout === 'fail' ? 'fail' : item.onTimeout === 'continue' ? 'continue' : undefined;
      if (item.onTimeout !== undefined && item.onTimeout !== 'fail' && item.onTimeout !== 'continue') {
        return { error: `${p}.onTimeout: Erlaubt sind "fail" oder "continue".` };
      }
      const timeoutMessage = typeof item.timeoutMessage === 'string' ? item.timeoutMessage : undefined;

      result.push({
        type: 'loop',
        ...(idRaw ? { id: idRaw } : {}),
        maxIterations: maxIter,
        ...(intervalSec > 0 ? { intervalSec } : {}),
        steps: bodyRes.steps!,
        ...(untilCond ? { until: untilCond } : {}),
        ...(onTimeout ? { onTimeout } : {}),
        ...(timeoutMessage !== undefined ? { timeoutMessage } : {}),
      });
    } else {
      return {
        error: `${p}.type: Unbekannter Schritt-Typ "${stepType}". Erlaubt: run, sleep, if, loop, set, log, stop, fail.`,
      };
    }
  }

  return { steps: result };
}

export function parseAndValidateWorkflow(rawJson: string): WorkflowValidationResult {
  const trimmed = rawJson.trim();
  if (!trimmed) {
    return { ok: false, error: 'Bitte geben Sie eine JSON-Workflow-Definition ein.' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (err) {
    return {
      ok: false,
      error: `Ungültiges JSON: ${err instanceof Error ? err.message : 'Syntaxfehler'}`,
    };
  }

  const rootObj: Record<string, unknown> = Array.isArray(parsed)
    ? { steps: parsed }
    : isRecord(parsed)
      ? parsed
      : {};

  if (!Array.isArray(rootObj.steps) || rootObj.steps.length === 0) {
    return {
      ok: false,
      error: 'Der JSON-Workflow benötigt ein nicht-leeres "steps"-Array.',
    };
  }

  const counters: ValidationCounters = {
    stepCount: 0,
    runCount: 0,
    conditionCount: 0,
    totalSleepSec: 0,
  };

  const stepsRes = validateSteps(rootObj.steps, 'steps', 0, counters);
  if (stepsRes.error) {
    return { ok: false, error: stepsRes.error };
  }
  if (counters.runCount === 0) {
    return {
      ok: false,
      error: 'Der JSON-Workflow muss mindestens einen "run"-Schritt mit einem SSH-Befehl enthalten.',
    };
  }

  let inputs: WorkflowInputDef[] | undefined;
  if (rootObj.inputs !== undefined && rootObj.inputs !== null) {
    if (!Array.isArray(rootObj.inputs)) {
      return { ok: false, error: '"inputs" muss ein JSON-Array aus Variablen-Definitionen sein.' };
    }
    if (rootObj.inputs.length > MAX_INPUTS) {
      return { ok: false, error: `"inputs" darf maximal ${MAX_INPUTS} Variablen enthalten.` };
    }
    const seenNames = new Set<string>();
    const parsedInputs: WorkflowInputDef[] = [];
    for (let i = 0; i < rootObj.inputs.length; i++) {
      const rawItem = rootObj.inputs[i];
      const p = `inputs[${i}]`;
      if (!isRecord(rawItem)) {
        return { ok: false, error: `${p}: Jede Eingabe-Variable muss ein JSON-Objekt sein.` };
      }
      const name = typeof rawItem.name === 'string' ? rawItem.name.trim() : '';
      if (!VALID_IDENT_RE.test(name)) {
        return {
          ok: false,
          error: `${p}.name: Ungültiger Variablenname "${name}" (erlaubt: Buchstaben, Ziffern, _, -).`,
        };
      }
      if (seenNames.has(name)) {
        return { ok: false, error: `${p}.name: Doppelter Variablenname "${name}".` };
      }
      seenNames.add(name);

      const inputType = typeof rawItem.type === 'string' ? rawItem.type.trim() : 'text';
      if (!VALID_INPUT_TYPES.has(inputType)) {
        return {
          ok: false,
          error: `${p}.type: Ungültiger Typ "${inputType}". Erlaubt: text, password, select, number, boolean.`,
        };
      }

      let options: string[] | undefined;
      if (rawItem.options !== undefined && rawItem.options !== null) {
        if (!Array.isArray(rawItem.options) || rawItem.options.length === 0 || rawItem.options.length > 100) {
          return {
            ok: false,
            error: `${p}.options: Muss ein nicht-leeres Array aus maximal 100 Auswahlwerten sein.`,
          };
        }
        options = rawItem.options.map((o) => String(o));
      }
      if (inputType === 'select' && (!options || options.length === 0)) {
        return {
          ok: false,
          error: `${p}.options: Für Typ "select" muss ein nicht-leeres "options"-Array angegeben werden.`,
        };
      }

      let defaultVal: string | number | boolean | undefined;
      if (rawItem.default !== undefined && rawItem.default !== null) {
        if (
          typeof rawItem.default === 'string' ||
          typeof rawItem.default === 'number' ||
          typeof rawItem.default === 'boolean'
        ) {
          defaultVal = rawItem.default;
        } else {
          defaultVal = String(rawItem.default);
        }
      }

      const secret = rawItem.secret !== undefined ? Boolean(rawItem.secret) : inputType === 'password';
      const label = typeof rawItem.label === 'string' && rawItem.label.trim() ? rawItem.label.trim() : undefined;
      const placeholder =
        typeof rawItem.placeholder === 'string' && rawItem.placeholder.trim()
          ? rawItem.placeholder.trim()
          : undefined;
      const description =
        typeof rawItem.description === 'string' && rawItem.description.trim()
          ? rawItem.description.trim()
          : undefined;

      parsedInputs.push({
        name,
        ...(label ? { label } : {}),
        type: inputType as WorkflowInputType,
        ...(options ? { options } : {}),
        ...(defaultVal !== undefined ? { default: defaultVal } : {}),
        ...(placeholder ? { placeholder } : {}),
        ...(description ? { description } : {}),
        ...(rawItem.required !== undefined ? { required: Boolean(rawItem.required) } : {}),
        ...(secret ? { secret: true } : {}),
      });
    }
    if (parsedInputs.length > 0) {
      inputs = parsedInputs;
    }
  }

  let vars: Record<string, string | number | boolean> | undefined;
  if (rootObj.vars !== undefined && rootObj.vars !== null) {
    if (!isRecord(rootObj.vars)) {
      return { ok: false, error: '"vars" muss ein JSON-Objekt aus Schlüssel-Wert-Paaren sein.' };
    }
    vars = {};
    for (const [k, v] of Object.entries(rootObj.vars)) {
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
        vars[k] = v;
      } else {
        vars[k] = JSON.stringify(v);
      }
    }
  }

  let output: WorkflowOutputConfig | undefined;
  if (rootObj.output !== undefined && rootObj.output !== null) {
    if (!isRecord(rootObj.output)) {
      return { ok: false, error: '"output" muss ein JSON-Objekt sein.' };
    }
    const fmt = typeof rootObj.output.format === 'string' ? rootObj.output.format.trim() : 'text';
    if (!VALID_FORMATS.has(fmt)) {
      return {
        ok: false,
        error: `output.format "${fmt}" ist ungültig. Erlaubt: text, template, table, json, lines.`,
      };
    }
    const filterRes = validateFilter(rootObj.output.filter, 'output.filter');
    if (filterRes.error) return { ok: false, error: filterRes.error };

    if (typeof rootObj.output.delimiter === 'string' && rootObj.output.delimiter.length > 0) {
      const err = validateRegex(rootObj.output.delimiter, '', 'output.delimiter');
      if (err) return { ok: false, error: err };
    }

    output = {
      format: fmt as WorkflowOutputConfig['format'],
      ...(typeof rootObj.output.template === 'string' ? { template: rootObj.output.template } : {}),
      ...(Array.isArray(rootObj.output.lines)
        ? { lines: rootObj.output.lines.map((l) => String(l)) }
        : {}),
      ...(typeof rootObj.output.source === 'string' ? { source: rootObj.output.source.trim() } : {}),
      ...(Array.isArray(rootObj.output.headers)
        ? { headers: rootObj.output.headers.map((h) => String(h)) }
        : {}),
      ...(Array.isArray(rootObj.output.columns)
        ? { columns: rootObj.output.columns.map((c) => Math.max(1, Math.floor(Number(c) || 1))) }
        : {}),
      ...(typeof rootObj.output.delimiter === 'string' ? { delimiter: rootObj.output.delimiter } : {}),
      ...(Array.isArray(rootObj.output.rows)
        ? {
            rows: rootObj.output.rows
              .filter(isRecord)
              .map((r) => ({ label: String(r.label ?? ''), value: String(r.value ?? '') })),
          }
        : {}),
      ...(isRecord(rootObj.output.fields)
        ? {
            fields: Object.fromEntries(
              Object.entries(rootObj.output.fields).map(([k, v]) => [
                k,
                typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
                  ? v
                  : String(v ?? ''),
              ])
            ),
          }
        : {}),
      ...(rootObj.output.autoType !== undefined ? { autoType: Boolean(rootObj.output.autoType) } : {}),
      ...(filterRes.filter ? { filter: filterRes.filter } : {}),
      ...(typeof rootObj.output.joinWith === 'string' ? { joinWith: rootObj.output.joinWith } : {}),
    };
  }

  const workflow: WorkflowDefinition = {
    stopOnError: rootObj.stopOnError !== undefined ? Boolean(rootObj.stopOnError) : true,
    ...(inputs && inputs.length > 0 ? { inputs } : {}),
    ...(vars && Object.keys(vars).length > 0 ? { vars } : {}),
    steps: stepsRes.steps!,
    ...(output ? { output } : {}),
  };

  const inputCount = inputs?.length ?? 0;
  const outputFormat = output?.format ?? 'default';
  const summaryParts = [
    ...(inputCount > 0 ? [`${inputCount} Var`] : []),
    `${counters.runCount} SSH`,
    ...(counters.conditionCount > 0 ? [`${counters.conditionCount} if`] : []),
    ...(counters.totalSleepSec > 0 ? [`${counters.totalSleepSec}s sleep`] : []),
    ...(output?.format ? [`output:${output.format}`] : []),
  ];

  return {
    ok: true,
    workflow,
    normalizedJson: JSON.stringify(workflow, null, 2),
    summary: {
      stepCount: counters.stepCount,
      runCount: counters.runCount,
      conditionCount: counters.conditionCount,
      totalSleepSec: counters.totalSleepSec,
      inputCount,
      outputFormat,
      previewLine: `JSON-Workflow (${summaryParts.join(' · ')})`,
    },
  };
}

export function redactWorkflowSecrets(text: string, secretValues: string[]): string {
  if (!text || secretValues.length === 0) return text;
  let out = text;
  for (const secret of secretValues) {
    if (secret.length > 0 && out.includes(secret)) {
      out = out.split(secret).join('********');
    }
  }
  return out;
}

export function sanitizeRuntimeVarsInput(
  raw: unknown
): { ok: true; vars: Record<string, string> } | { ok: false; error: string } {
  if (raw === undefined || raw === null) {
    return { ok: true, vars: {} };
  }
  if (!isRecord(raw)) {
    return { ok: false, error: 'workflowVars muss ein JSON-Objekt aus Schlüssel-Wert-Paaren sein.' };
  }
  const entries = Object.entries(raw);
  if (entries.length > MAX_RUNTIME_VARS) {
    return { ok: false, error: `Es sind maximal ${MAX_RUNTIME_VARS} Laufzeit-Variablen zulässig.` };
  }
  const clean: Record<string, string> = {};
  for (const [k, v] of entries) {
    const key = k.trim();
    if (!VALID_IDENT_RE.test(key)) {
      return {
        ok: false,
        error: `Ungültiger Variablenname "${k}" (erlaubt: Buchstaben, Ziffern, _, -).`,
      };
    }
    if (v === undefined || v === null) continue;
    const strVal = typeof v === 'string' ? v : String(v);
    if (strVal.length > MAX_VAR_VALUE_LEN) {
      return {
        ok: false,
        error: `Wert für Variable "${key}" überschreitet das Limit von ${MAX_VAR_VALUE_LEN} Zeichen.`,
      };
    }
    clean[key] = strVal;
  }
  return { ok: true, vars: clean };
}

export function resolveWorkflowRuntimeVars(
  workflow: WorkflowDefinition,
  runtimeVars?: Record<string, string>
):
  | { ok: true; vars: Record<string, string>; secretValues: string[]; secretKeys: Set<string> }
  | { ok: false; error: string } {
  const sanitized = sanitizeRuntimeVarsInput(runtimeVars);
  if (!sanitized.ok) return sanitized;

  const merged: Record<string, string> = {};
  for (const [k, v] of Object.entries(workflow.vars ?? {})) {
    merged[k] = String(v);
  }
  for (const inp of workflow.inputs ?? []) {
    if (inp.default !== undefined && merged[inp.name] === undefined) {
      merged[inp.name] = String(inp.default);
    }
  }
  for (const [k, v] of Object.entries(sanitized.vars)) {
    merged[k] = v;
  }

  const secretKeys = new Set<string>();
  const secretSet = new Set<string>();

  for (const inp of workflow.inputs ?? []) {
    const label = inp.label || inp.name;
    const val = merged[inp.name] ?? '';
    const trimmed = val.trim();

    if (inp.required && trimmed.length === 0) {
      return {
        ok: false,
        error: `Pflicht-Variable "${label}" (${inp.name}) muss vor der Ausführung angegeben werden.`,
      };
    }
    if (inp.type === 'select' && inp.options && trimmed.length > 0 && !inp.options.includes(val)) {
      return {
        ok: false,
        error: `Ungültiger Wert für Variable "${label}" (${inp.name}). Erlaubt: ${inp.options.join(', ')}.`,
      };
    }
    if (inp.type === 'number' && trimmed.length > 0 && !Number.isFinite(Number(trimmed))) {
      return {
        ok: false,
        error: `Variable "${label}" (${inp.name}) muss eine gültige Zahl sein.`,
      };
    }
    if (
      inp.type === 'boolean' &&
      trimmed.length > 0 &&
      !['true', 'false', '1', '0'].includes(trimmed.toLowerCase())
    ) {
      return {
        ok: false,
        error: `Variable "${label}" (${inp.name}) muss "true" oder "false" sein.`,
      };
    }

    if (inp.type === 'password' || inp.secret) {
      secretKeys.add(inp.name);
      if (val.length > 0) {
        secretSet.add(val);
      }
    }
  }

  // Sort longest first so shorter substrings do not partially mask longer secrets
  const secretValues = Array.from(secretSet).sort((a, b) => b.length - a.length);
  return { ok: true, vars: merged, secretValues, secretKeys };
}

export function applyOutputFilter(input: string, filter?: OutputFilter): string {
  if (!filter) return input;

  let text = input.replace(/\r\n/g, '\n');
  if (filter.trim) {
    text = text.trim();
  }

  if (filter.replace && filter.replace.length > 0) {
    for (const rule of filter.replace) {
      const re = new RegExp(rule.pattern, rule.flags ?? 'g');
      text = text.replace(re, rule.with);
    }
  }

  let lines = text.length === 0 ? [] : text.split('\n');
  const ciFlags = filter.caseInsensitive ? 'i' : '';

  if (filter.dropEmpty) {
    lines = lines.filter((l) => l.trim().length > 0);
  }

  if (filter.include) {
    const re = new RegExp(filter.include, ciFlags);
    lines = lines.filter((l) => re.test(l));
  }

  if (filter.exclude) {
    const re = new RegExp(filter.exclude, ciFlags);
    lines = lines.filter((l) => !re.test(l));
  }

  if (filter.regex) {
    const groupIdx = filter.regexGroup ?? 0;
    if (filter.regexAll) {
      const re = new RegExp(filter.regex, `${ciFlags}g`);
      const matches: string[] = [];
      for (const line of lines) {
        for (const m of line.matchAll(re)) {
          const val = m[groupIdx] ?? m[0];
          if (val !== undefined) matches.push(val);
        }
      }
      lines = matches;
    } else {
      const re = new RegExp(filter.regex, ciFlags);
      const extracted: string[] = [];
      for (const line of lines) {
        const m = line.match(re);
        if (m) {
          const val = m[groupIdx] ?? m[0];
          if (val !== undefined) extracted.push(val);
        }
      }
      lines = extracted;
    }
  }

  if (filter.columns && filter.columns.length > 0) {
    const delimRe = new RegExp(filter.delimiter || '\\s+');
    const joiner = filter.columnJoin ?? ' ';
    lines = lines.map((line) => {
      const parts = line.trim().split(delimRe);
      return filter.columns!
        .map((colIdx) => parts[colIdx - 1] ?? '')
        .join(joiner)
        .trim();
    });
  }

  if (filter.dropEmpty) {
    lines = lines.filter((l) => l.trim().length > 0);
  }

  if (filter.sort) {
    lines = [...lines].sort((a, b) => a.localeCompare(b));
  }

  if (filter.unique) {
    const seen = new Set<string>();
    lines = lines.filter((l) => {
      if (seen.has(l)) return false;
      seen.add(l);
      return true;
    });
  }

  if (filter.head && filter.head > 0) {
    lines = lines.slice(0, filter.head);
  }

  if (filter.tail && filter.tail > 0) {
    lines = lines.slice(-filter.tail);
  }

  if (filter.prefix || filter.suffix) {
    const pre = filter.prefix ?? '';
    const suf = filter.suffix ?? '';
    lines = lines.map((l) => `${pre}${l}${suf}`);
  }

  const result = lines.join(filter.joinWith ?? '\n');
  return filter.trim ? result.trim() : result;
}

function resolvePath(pathStr: string, ctx: WorkflowContext): string {
  const key = pathStr.trim();
  if (!key) return '';

  if (key === 'target.ip') return ctx.target.ip;
  if (key === 'target.port') return String(ctx.target.port);
  if (key === 'target.user') return ctx.target.user;
  if (key === 'target.label') return ctx.target.label;

  if (key.startsWith('vars.')) {
    const varName = key.slice(5);
    return ctx.vars[varName] ?? '';
  }

  const normalized = key.startsWith('steps.') ? key.slice(6) : key;
  const dotIdx = normalized.indexOf('.');
  if (dotIdx > 0) {
    const targetId = normalized.slice(0, dotIdx);
    const field = normalized.slice(dotIdx + 1);
    const rec = targetId === 'last' ? ctx.last : ctx.steps[targetId];
    if (!rec) return '';
    switch (field) {
      case 'stdout':
      case 'filtered':
        return rec.stdout;
      case 'rawStdout':
        return rec.rawStdout;
      case 'stderr':
        return rec.stderr;
      case 'exitCode':
        return String(rec.exitCode);
      case 'ok':
        return rec.ok ? 'true' : 'false';
      case 'linesCount':
        return String(rec.linesCount);
      default:
        return '';
    }
  }

  if (ctx.vars[key] !== undefined) return ctx.vars[key];
  if (ctx.steps[key]) return ctx.steps[key].stdout;
  return '';
}

export function interpolateTemplate(template: string, ctx: WorkflowContext): string {
  return template.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (_m, pathExpr: string) =>
    resolvePath(pathExpr, ctx)
  );
}

function parseNumeric(val: unknown): number | null {
  if (typeof val === 'number') return Number.isFinite(val) ? val : null;
  if (typeof val === 'boolean') return val ? 1 : 0;
  const s = String(val ?? '').trim();
  if (!s) return null;
  const m = s.match(/-?\d+(?:[.,]\d+)?/);
  if (!m) return null;
  const n = Number(m[0].replace(',', '.'));
  return Number.isFinite(n) ? n : null;
}

export function evaluateCondition(cond: WorkflowCondition, ctx: WorkflowContext): boolean {
  if (!('op' in cond)) {
    if (cond.all && !cond.all.every((c) => evaluateCondition(c, ctx))) return false;
    if (cond.any && !cond.any.some((c) => evaluateCondition(c, ctx))) return false;
    if (cond.not && evaluateCondition(cond.not, ctx)) return false;
    return true;
  }

  const from = cond.from?.trim() || 'last';
  const field = cond.field || 'stdout';

  let actualStr = '';
  if (from.startsWith('vars.')) {
    actualStr = ctx.vars[from.slice(5)] ?? '';
  } else if (from.startsWith('target.')) {
    actualStr = resolvePath(from, ctx);
  } else if (ctx.vars[from] !== undefined && !ctx.steps[from] && from !== 'last') {
    actualStr = ctx.vars[from];
  } else {
    const rec = from === 'last' ? ctx.last : ctx.steps[from];
    if (rec) {
      switch (field) {
        case 'stdout':
          actualStr = rec.stdout;
          break;
        case 'rawStdout':
          actualStr = rec.rawStdout;
          break;
        case 'stderr':
          actualStr = rec.stderr;
          break;
        case 'exitCode':
          actualStr = String(rec.exitCode);
          break;
        case 'ok':
          actualStr = rec.ok ? 'true' : 'false';
          break;
        case 'linesCount':
          actualStr = String(rec.linesCount);
          break;
      }
    }
  }

  const expectedRaw =
    typeof cond.value === 'string' ? interpolateTemplate(cond.value, ctx) : String(cond.value ?? '');
  const ci = Boolean(cond.caseInsensitive);
  const lhs = ci ? actualStr.toLowerCase() : actualStr;
  const rhs = ci ? expectedRaw.toLowerCase() : expectedRaw;

  switch (cond.op) {
    case 'equals':
    case '==':
      return lhs.trim() === rhs.trim();
    case 'notEquals':
    case '!=':
      return lhs.trim() !== rhs.trim();
    case 'contains':
      return lhs.includes(rhs);
    case 'notContains':
      return !lhs.includes(rhs);
    case 'startsWith':
      return lhs.trim().startsWith(rhs);
    case 'endsWith':
      return lhs.trim().endsWith(rhs);
    case 'matches':
      return new RegExp(expectedRaw, ci ? 'i' : '').test(actualStr);
    case 'notMatches':
      return !new RegExp(expectedRaw, ci ? 'i' : '').test(actualStr);
    case 'isEmpty':
      return actualStr.trim().length === 0;
    case 'isNotEmpty':
      return actualStr.trim().length > 0;
    case 'gt':
    case '>': {
      const a = parseNumeric(actualStr);
      const b = parseNumeric(expectedRaw);
      return a !== null && b !== null && a > b;
    }
    case 'gte':
    case '>=': {
      const a = parseNumeric(actualStr);
      const b = parseNumeric(expectedRaw);
      return a !== null && b !== null && a >= b;
    }
    case 'lt':
    case '<': {
      const a = parseNumeric(actualStr);
      const b = parseNumeric(expectedRaw);
      return a !== null && b !== null && a < b;
    }
    case 'lte':
    case '<=': {
      const a = parseNumeric(actualStr);
      const b = parseNumeric(expectedRaw);
      return a !== null && b !== null && a <= b;
    }
    default:
      return false;
  }
}

function renderAsciiTable(headers: string[], rows: string[][]): string {
  const colCount = Math.max(headers.length, ...rows.map((r) => r.length));
  if (colCount === 0) return '';
  const widths = Array.from({ length: colCount }, (_, colIdx) => {
    const headerLen = (headers[colIdx] ?? '').length;
    const maxRowLen = rows.reduce((max, r) => Math.max(max, (r[colIdx] ?? '').length), 0);
    return Math.max(headerLen, maxRowLen, 1);
  });

  const formatRow = (cells: string[]) =>
    widths.map((w, idx) => (cells[idx] ?? '').padEnd(w, ' ')).join(' | ');

  const lines: string[] = [];
  if (headers.length > 0) {
    lines.push(formatRow(headers));
    lines.push(widths.map((w) => '-'.repeat(w)).join('-+-'));
  }
  for (const r of rows) {
    lines.push(formatRow(r));
  }
  return lines.join('\n');
}

export function formatWorkflowOutput(workflow: WorkflowDefinition, ctx: WorkflowContext): string {
  const outCfg = workflow.output;
  if (!outCfg) {
    const parts: string[] = [];
    for (const rec of ctx.stepOrder) {
      if (!rec.silent && rec.stdout.trim().length > 0) {
        parts.push(rec.stdout.trimEnd());
      }
    }
    for (const logLine of ctx.logs) {
      parts.push(logLine);
    }
    return parts.join('\n');
  }

  const fmt = outCfg.format ?? 'text';

  if (fmt === 'template' || fmt === 'text') {
    let rendered = '';
    if (typeof outCfg.template === 'string') {
      rendered = interpolateTemplate(outCfg.template, ctx);
    } else if (Array.isArray(outCfg.lines)) {
      rendered = outCfg.lines.map((l) => interpolateTemplate(l, ctx)).join('\n');
    } else {
      const sourceText = outCfg.source ? resolvePath(`${outCfg.source}.stdout`, ctx) : ctx.logs.join('\n');
      rendered = sourceText;
    }
    return applyOutputFilter(rendered, outCfg.filter);
  }

  if (fmt === 'json') {
    const autoType = outCfg.autoType !== false;
    const obj: Record<string, unknown> = {};
    if (outCfg.fields) {
      for (const [k, v] of Object.entries(outCfg.fields)) {
        if (typeof v === 'string') {
          const interpolated = interpolateTemplate(v, ctx);
          if (autoType) {
            const trimmed = interpolated.trim();
            if (trimmed === 'true') obj[k] = true;
            else if (trimmed === 'false') obj[k] = false;
            else if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) obj[k] = Number(trimmed);
            else obj[k] = interpolated;
          } else {
            obj[k] = interpolated;
          }
        } else {
          obj[k] = v;
        }
      }
    } else {
      const secretKeys = new Set(
        (workflow.inputs ?? [])
          .filter((i) => i.type === 'password' || i.secret)
          .map((i) => i.name)
      );
      obj.target = ctx.target;
      obj.vars = Object.fromEntries(
        Object.entries(ctx.vars).map(([k, v]) => [k, secretKeys.has(k) ? '********' : v])
      );
      obj.steps = Object.fromEntries(
        Object.entries(ctx.steps).map(([id, rec]) => [
          id,
          { exitCode: rec.exitCode, ok: rec.ok, stdout: rec.stdout },
        ])
      );
      if (ctx.logs.length > 0) obj.logs = ctx.logs;
    }
    const jsonText = JSON.stringify(obj, null, 2);
    return applyOutputFilter(jsonText, outCfg.filter);
  }

  if (fmt === 'table') {
    let tableText = '';
    if (outCfg.rows && outCfg.rows.length > 0) {
      const headers = outCfg.headers && outCfg.headers.length >= 2 ? outCfg.headers : ['Feld', 'Wert'];
      const rows = outCfg.rows.map((r) => [
        interpolateTemplate(r.label, ctx),
        interpolateTemplate(r.value, ctx).replace(/\s*\n\s*/g, ' / '),
      ]);
      tableText = renderAsciiTable(headers, rows);
    } else if (outCfg.fields && Object.keys(outCfg.fields).length > 0) {
      const headers = outCfg.headers && outCfg.headers.length >= 2 ? outCfg.headers : ['Feld', 'Wert'];
      const rows = Object.entries(outCfg.fields).map(([k, v]) => [
        k,
        interpolateTemplate(String(v), ctx).replace(/\s*\n\s*/g, ' / '),
      ]);
      tableText = renderAsciiTable(headers, rows);
    } else {
      const src = outCfg.source ? resolvePath(`${outCfg.source}.stdout`, ctx) : ctx.last?.stdout ?? '';
      const filtered = applyOutputFilter(src, outCfg.filter);
      const delim = new RegExp(outCfg.delimiter || '\\s+');
      const rawLines = filtered
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const rows = rawLines.map((line) => {
        const parts = line.split(delim);
        if (outCfg.columns && outCfg.columns.length > 0) {
          return outCfg.columns.map((c) => parts[c - 1] ?? '');
        }
        return parts;
      });
      tableText = renderAsciiTable(outCfg.headers ?? [], rows);
    }
    return tableText;
  }

  // fmt === 'lines'
  let raw = '';
  if (outCfg.source && outCfg.source !== 'all') {
    raw = resolvePath(`${outCfg.source}.stdout`, ctx);
  } else {
    const parts = [
      ...ctx.stepOrder.filter((r) => !r.silent && r.stdout.trim()).map((r) => r.stdout.trimEnd()),
      ...ctx.logs,
    ];
    raw = parts.join('\n');
  }
  const effectiveFilter: OutputFilter = {
    ...(outCfg.filter ?? {}),
    ...(outCfg.joinWith !== undefined ? { joinWith: outCfg.joinWith } : {}),
  };
  return applyOutputFilter(raw, effectiveFilter);
}

export async function executeWorkflowEngine(params: {
  workflow: WorkflowDefinition;
  target: WorkflowTargetInfo;
  timeoutSec: number;
  runtimeVars?: Record<string, string>;
  runRemoteCommand: (
    commandText: string,
    remainingTimeoutMs: number
  ) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
  sleepFn?: (ms: number) => Promise<void>;
}): Promise<WorkflowExecutionResult> {
  const started = Date.now();
  const totalBudgetMs = Math.max(5000, params.timeoutSec * 1000);
  const sleep = params.sleepFn ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));

  const resolved = resolveWorkflowRuntimeVars(params.workflow, params.runtimeVars);
  if (!resolved.ok) {
    return {
      exitCode: 2,
      stdout: '',
      stderr: resolved.error,
      executedSteps: 0,
      commandsRun: [],
    };
  }

  const ctx: WorkflowContext = {
    target: params.target,
    vars: resolved.vars,
    steps: {},
    stepOrder: [],
    last: null,
    logs: [],
    stderrParts: [],
    executedCount: 0,
    stopped: false,
    finalExitCode: 0,
  };
  const commandsRun: string[] = [];

  const remainingMs = () => totalBudgetMs - (Date.now() - started);

  async function runBlock(steps: WorkflowStep[]): Promise<void> {
    for (const step of steps) {
      if (ctx.stopped) return;
      if (ctx.executedCount >= MAX_EXECUTED_STEPS) {
        ctx.stderrParts.push(`Workflow abgebrochen: Maximale Schrittanzahl (${MAX_EXECUTED_STEPS}) erreicht.`);
        ctx.finalExitCode = 125;
        ctx.stopped = true;
        return;
      }
      const rem = remainingMs();
      if (rem <= 250) {
        ctx.stderrParts.push(`Workflow nach ${params.timeoutSec} Sekunden abgebrochen (Timeout).`);
        ctx.finalExitCode = 124;
        ctx.stopped = true;
        return;
      }

      ctx.executedCount++;

      if (step.type === 'run') {
        const renderedCmd = interpolateTemplate(step.command, ctx);
        commandsRun.push(step.silent ? step.command : renderedCmd);
        const res = await params.runRemoteCommand(renderedCmd, rem);
        const rawStdout = res.stdout.replace(/\r\n/g, '\n');
        const filteredStdout = applyOutputFilter(rawStdout, step.filter);
        const linesCount = filteredStdout.trim()
          ? filteredStdout.trim().split('\n').length
          : 0;
        const stepId = step.id || step.saveAs || `step_${ctx.stepOrder.length + 1}`;
        const record: WorkflowStepRecord = {
          id: stepId,
          command: renderedCmd,
          exitCode: res.exitCode,
          ok: res.exitCode === 0,
          stdout: filteredStdout,
          rawStdout,
          stderr: res.stderr,
          linesCount,
          silent: Boolean(step.silent),
        };
        ctx.steps[stepId] = record;
        ctx.stepOrder.push(record);
        ctx.last = record;

        if (res.stderr.trim()) {
          ctx.stderrParts.push(`[${stepId}] ${res.stderr.trim()}`);
        }

        const shouldStopOnError =
          step.continueOnError !== undefined
            ? !step.continueOnError
            : params.workflow.stopOnError !== false;

        if (res.exitCode !== 0 && shouldStopOnError) {
          ctx.finalExitCode = res.exitCode;
          ctx.stopped = true;
          return;
        }

        if (step.sleepAfterSec && step.sleepAfterSec > 0) {
          const waitMs = Math.min(step.sleepAfterSec * 1000, Math.max(0, remainingMs()));
          if (waitMs > 0) await sleep(waitMs);
        }
      } else if (step.type === 'sleep') {
        const waitMs = Math.min(step.seconds * 1000, Math.max(0, remainingMs()));
        if (waitMs > 0) await sleep(waitMs);
      } else if (step.type === 'if') {
        const matched = evaluateCondition(step.when, ctx);
        if (matched) {
          await runBlock(step.then);
        } else if (step.else && step.else.length > 0) {
          await runBlock(step.else);
        }
      } else if (step.type === 'loop') {
        let satisfied = false;
        const maxIter = Math.min(120, Math.max(1, step.maxIterations || 1));
        for (let iter = 1; iter <= maxIter; iter++) {
          if (ctx.stopped) break;
          ctx.vars.loopIteration = String(iter);
          if (step.id) {
            ctx.vars[`${step.id}_attempts`] = String(iter);
          }
          await runBlock(step.steps);
          if (ctx.stopped) break;
          if (step.until && evaluateCondition(step.until, ctx)) {
            satisfied = true;
            break;
          }
          if (iter < maxIter && step.intervalSec && step.intervalSec > 0) {
            const waitMs = Math.min(step.intervalSec * 1000, Math.max(0, remainingMs()));
            if (waitMs <= 0) {
              ctx.stderrParts.push(`Workflow nach ${params.timeoutSec} Sekunden abgebrochen (Timeout).`);
              ctx.finalExitCode = 124;
              ctx.stopped = true;
              break;
            }
            await sleep(waitMs);
          }
        }
        if (!ctx.stopped && step.until && !satisfied && step.onTimeout === 'fail') {
          const msg = step.timeoutMessage
            ? interpolateTemplate(step.timeoutMessage, ctx)
            : `Schleifen-Bedingung nach ${maxIter} Versuchen nicht erfüllt.`;
          ctx.stderrParts.push(msg);
          ctx.finalExitCode = 124;
          ctx.stopped = true;
          return;
        }
      } else if (step.type === 'set') {
        const rawVal = interpolateTemplate(step.value, ctx);
        ctx.vars[step.name] = applyOutputFilter(rawVal, step.filter);
      } else if (step.type === 'log') {
        ctx.logs.push(interpolateTemplate(step.message, ctx));
      } else if (step.type === 'stop' || step.type === 'fail') {
        if (step.message) {
          const msg = interpolateTemplate(step.message, ctx);
          if (step.type === 'fail') {
            ctx.stderrParts.push(msg);
          } else {
            ctx.logs.push(msg);
          }
        }
        ctx.finalExitCode = step.exitCode ?? (step.type === 'fail' ? 1 : 0);
        ctx.stopped = true;
        return;
      }
    }
  }

  await runBlock(params.workflow.steps);

  const formattedStdout = formatWorkflowOutput(params.workflow, ctx);
  const redact = (s: string) => redactWorkflowSecrets(s, resolved.secretValues);
  return {
    exitCode: ctx.finalExitCode,
    stdout: redact(formattedStdout),
    stderr: redact(ctx.stderrParts.join('\n')),
    executedSteps: ctx.executedCount,
    commandsRun: commandsRun.map(redact),
  };
}

export interface WorkflowTemplatePreset {
  id: string;
  labelDe: string;
  labelEn: string;
  descriptionDe: string;
  descriptionEn: string;
  category: string;
  timeoutSec: number;
  json: string;
}

export const WORKFLOW_TEMPLATES: WorkflowTemplatePreset[] = [
  {
    id: 'service-heal',
    labelDe: 'Dienst prüfen & bei Bedarf neu starten (Wenn/Dann + Sleep)',
    labelEn: 'Check service & restart if needed (If/Then + Sleep)',
    descriptionDe:
      'Prüft einen Systemd-Dienst, startet ihn bei Inaktivität mit Pause neu und gibt einen formatierten Statusbericht aus.',
    descriptionEn:
      'Checks a systemd service, restarts it with a pause if inactive, and prints a formatted status summary.',
    category: 'Dienste',
    timeoutSec: 30,
    json: JSON.stringify(
      {
        stopOnError: true,
        inputs: [
          {
            name: 'service',
            label: 'Systemd-Dienst',
            type: 'text',
            default: 'nginx',
            placeholder: 'z. B. nginx, postgresql, docker',
            required: true,
          },
        ],
        steps: [
          {
            type: 'run',
            id: 'check',
            command: 'systemctl is-active {{vars.service}}',
            continueOnError: true,
            filter: { trim: true },
          },
          {
            type: 'if',
            when: { from: 'check', field: 'stdout', op: 'notEquals', value: 'active' },
            then: [
              { type: 'run', id: 'restart', command: 'systemctl restart {{vars.service}}' },
              { type: 'sleep', seconds: 3 },
              {
                type: 'run',
                id: 'verify',
                command: 'systemctl is-active {{vars.service}}',
                continueOnError: true,
                filter: { trim: true },
              },
              { type: 'set', name: 'action', value: 'Neu gestartet' },
              { type: 'set', name: 'finalState', value: '{{verify.stdout}}' },
            ],
            else: [
              { type: 'set', name: 'action', value: 'Keine Aktion nötig' },
              { type: 'set', name: 'finalState', value: '{{check.stdout}}' },
            ],
          },
        ],
        output: {
          format: 'table',
          headers: ['Eigenschaft', 'Wert'],
          rows: [
            { label: 'Server', value: '{{target.label}} ({{target.ip}})' },
            { label: 'Dienst', value: '{{vars.service}}' },
            { label: 'Vorher', value: '{{check.stdout}} (Exit {{check.exitCode}})' },
            { label: 'Aktion', value: '{{vars.action}}' },
            { label: 'Aktueller Status', value: '{{vars.finalState}}' },
          ],
        },
      },
      null,
      2
    ),
  },
  {
    id: 'disk-threshold',
    labelDe: 'Festplatte filtern & Schwellenwert prüfen (>= 80%)',
    labelEn: 'Filter disk usage & check threshold (>= 80%)',
    descriptionDe:
      'Filtert lokale Laufwerke, extrahiert die Root-Auslastung per Regex, warnt ab 80 % und formatiert als Tabelle.',
    descriptionEn:
      'Filters local filesystems, extracts root usage via regex, warns above 80%, and formats the result as a table.',
    category: 'Diagnose',
    timeoutSec: 20,
    json: JSON.stringify(
      {
        stopOnError: true,
        steps: [
          {
            type: 'run',
            id: 'root_pct',
            command: 'df -P / | tail -n 1',
            silent: true,
            filter: { regex: '(\\d+)%', regexGroup: 1, trim: true },
          },
          {
            type: 'run',
            id: 'disks',
            command: 'df -hP -x tmpfs -x devtmpfs',
            filter: { exclude: '^Filesystem', dropEmpty: true },
          },
          {
            type: 'if',
            when: { from: 'root_pct', field: 'stdout', op: 'gte', value: 80 },
            then: [
              { type: 'set', name: 'status', value: 'WARNUNG: Root-Partition bei {{root_pct.stdout}}%' },
            ],
            else: [
              { type: 'set', name: 'status', value: 'OK (Root-Partition: {{root_pct.stdout}}%)' },
            ],
          },
        ],
        output: {
          format: 'template',
          template:
            'Host: {{target.label}} ({{target.ip}})\nBewertung: {{vars.status}}\n\nLaufwerke:\n{{disks.stdout}}',
        },
      },
      null,
      2
    ),
  },
  {
    id: 'system-json-report',
    labelDe: 'System-Bericht als strukturiertes JSON',
    labelEn: 'Structured JSON System Report',
    descriptionDe:
      'Sammelt Hostname, Kernel, Uptime und fehlgeschlagene Units und gibt ein sauberes JSON-Objekt zurück.',
    descriptionEn:
      'Collects hostname, kernel, uptime, and failed systemd units and formats a clean JSON report.',
    category: 'Diagnose',
    timeoutSec: 20,
    json: JSON.stringify(
      {
        stopOnError: false,
        steps: [
          { type: 'run', id: 'host', command: 'hostname -f', filter: { trim: true } },
          { type: 'run', id: 'kernel', command: 'uname -r', filter: { trim: true } },
          {
            type: 'run',
            id: 'load',
            command: 'uptime',
            filter: { regex: 'load average:\\s*(.+)$', regexGroup: 1, trim: true },
          },
          {
            type: 'run',
            id: 'failed',
            command: 'systemctl --failed --no-legend --plain',
            continueOnError: true,
            filter: { dropEmpty: true, columns: [1] },
          },
          {
            type: 'if',
            when: { from: 'failed', field: 'linesCount', op: 'equals', value: 0 },
            then: [{ type: 'set', name: 'healthy', value: 'true' }],
            else: [{ type: 'set', name: 'healthy', value: 'false' }],
          },
        ],
        output: {
          format: 'json',
          fields: {
            server: '{{target.label}}',
            ip: '{{target.ip}}',
            hostname: '{{host.stdout}}',
            kernel: '{{kernel.stdout}}',
            loadAverage: '{{load.stdout}}',
            failedUnitsCount: '{{failed.linesCount}}',
            healthy: '{{vars.healthy}}',
          },
        },
      },
      null,
      2
    ),
  },
  {
    id: 'dell-idrac-reset',
    labelDe: 'Dell iDRAC Werksreset (Loop + Variablen)',
    labelEn: 'Dell iDRAC Factory Reset (Loop + Variables)',
    descriptionDe:
      'Setzt Dell iDRAC per racadm zurück, wartet per Schleife auf "dedicated", konfiguriert NIC & DHCP und setzt das Passwort per Eingabevariable.',
    descriptionEn:
      'Resets Dell iDRAC via racadm, polls in a loop until "dedicated", configures NIC & DHCP, and sets the user password via runtime variables.',
    category: 'Wartung',
    timeoutSec: 600,
    json: JSON.stringify(
      {
        stopOnError: true,
        inputs: [
          {
            name: 'nicSelection',
            label: 'Netzwerkkartenoption (iDRAC NIC)',
            type: 'select',
            options: ['LOM1', 'LOM3', 'dedicated'],
            default: 'LOM1',
            required: true,
          },
          {
            name: 'idracPassword',
            label: 'Neues iDRAC-Passwort (User 2)',
            type: 'password',
            placeholder: 'Neues Passwort eingeben...',
            required: true,
            secret: true,
          },
        ],
        steps: [
          {
            type: 'run',
            id: 'reset_all',
            command: 'racadm racresetcfg -all',
            sleepAfterSec: 20,
            filter: { trim: true },
          },
          {
            type: 'loop',
            id: 'wait_reset',
            maxIterations: 30,
            intervalSec: 10,
            steps: [
              {
                type: 'run',
                id: 'poll_nic',
                command: 'racadm get idrac.nic.selection',
                continueOnError: true,
                silent: true,
                filter: { trim: true },
              },
            ],
            until: {
              from: 'poll_nic',
              field: 'stdout',
              op: 'contains',
              value: 'dedicated',
              caseInsensitive: true,
            },
            onTimeout: 'fail',
            timeoutMessage:
              'Timeout: iDRAC auf {{target.ip}} hat nach 30 Versuchen (~5 Minuten) nicht "dedicated" zurückgemeldet.',
          },
          { type: 'sleep', seconds: 60 },
          {
            type: 'run',
            id: 'set_nic',
            command: 'racadm set idrac.nic.selection "{{vars.nicSelection}}"',
            sleepAfterSec: 5,
            filter: { trim: true },
          },
          {
            type: 'run',
            id: 'set_niccfg',
            command: 'racadm setniccfg -d',
            sleepAfterSec: 5,
            filter: { trim: true },
          },
          {
            type: 'run',
            id: 'set_password',
            command: 'racadm set idrac.users.2.password "{{vars.idracPassword}}"',
            sleepAfterSec: 5,
            silent: true,
            filter: { trim: true },
          },
          {
            type: 'set',
            name: 'passwordResult',
            value: 'Gesetzt (Exit {{set_password.exitCode}})',
          },
        ],
        output: {
          format: 'table',
          headers: ['Schritt / Eigenschaft', 'Ergebnis'],
          rows: [
            { label: 'Ziel-iDRAC', value: '{{target.label}} ({{target.ip}})' },
            { label: '1. Werksreset', value: 'Exit {{reset_all.exitCode}} · {{reset_all.stdout}}' },
            { label: '2. Reset-Polling', value: 'Erfolgreich nach {{vars.wait_reset_attempts}} Versuch(en)' },
            { label: '3. NIC-Option ({{vars.nicSelection}})', value: 'Exit {{set_nic.exitCode}} · {{set_nic.stdout}}' },
            { label: '4. DHCP', value: 'Exit {{set_niccfg.exitCode}} · {{set_niccfg.stdout}}' },
            { label: '5. Benutzerpasswort', value: '{{vars.passwordResult}}' },
          ],
        },
      },
      null,
      2
    ),
  },
];
