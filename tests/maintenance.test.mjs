import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';
const source = await readFile(new URL('../src/maintenance.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { canDisableStartup, maintenanceRows, startupLabel } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
const entry = (id, kind = 'run', startupState = 'registered') => ({ id, name: id, kind, startupState });
const backup = (id, value, action = 'disable', status = 'removed') => ({ id, entry: value, action, status });

test('startup rows retain disabled entries across reloads without duplicating a re-registered app', () => {
  const live = entry('Current');
  const report = { entries: [live, entry('App path', 'app_path'), entry('Shortcut', 'startup_folder')] };
  const backups = [backup(1, entry('Disabled')), backup(2, entry('Disabled')), backup(3, live), backup(4, entry('Failed'), 'disable', 'failed'), backup(5, entry('Restored'), 'disable', 'restored'), backup(6, entry('Cleaned'), 'clean')];
  const rows = maintenanceRows(report, backups, true);
  assert.deepEqual(rows.map(row => row.entry.id), ['Current', 'Disabled', 'Shortcut']);
  assert.equal(rows.find(row => row.entry.id === 'Disabled').backup.id, 1);
  assert.equal(rows.find(row => row.entry.id === 'Current').backup, undefined);
  assert.equal(maintenanceRows(null, backups, true).length, 2);
});

test('registry lists contain only registry values and never include disabled-file backups', () => {
  const rows = maintenanceRows({ entries: [entry('Run'), entry('App', 'app_path'), entry('Folder', 'startup_folder')] }, [backup(1, entry('Disabled'))], false);
  assert.deepEqual(rows.map(row => row.entry.id), ['App', 'Run']);
});

test('startup statuses distinguish Windows disables, cleaner disables and one-time entries', () => {
  assert.equal(startupLabel({ entry: entry('App', 'run', 'windows_disabled') }), 'Disabled in Windows');
  assert.equal(startupLabel({ entry: entry('App'), backup: backup(1, entry('App')) }), 'Disabled here');
  assert.equal(startupLabel({ entry: entry('App', 'run_once', 'once') }), 'One time');
  assert.equal(startupLabel({ entry: entry('App', 'run', 'unknown') }), 'State unknown');
  assert.equal(canDisableStartup({ ...entry('App', 'run', 'windows_disabled'), canDisable: true }), false);
  assert.equal(canDisableStartup({ ...entry('App'), canDisable: true }), true);
});
