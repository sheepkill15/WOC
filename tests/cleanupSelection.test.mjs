import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';

const source = await readFile(new URL('../src/cleanupSelection.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { remainingCleanupSelection } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

test('a moved ancestor clears covered selections across Windows case and separator variations', () => {
  const selected = new Set(['C:/Data/OldApp', 'C:/Data/OldApp/Cache', 'C:/Data/OldApp2']);
  const outcome = { items: [{ path: 'c:\\data\\oldapp', moved: true }] };
  assert.deepEqual([...remainingCleanupSelection(selected, outcome)], ['C:/Data/OldApp2']);
});

test('partial cleanup preserves selections whose moves failed', () => {
  const selected = new Set(['C:\\Data\\One', 'C:\\Data\\Two']);
  const outcome = { items: [{ path: 'C:\\Data\\One', moved: true }, { path: 'C:\\Data\\Two', moved: false }] };
  assert.deepEqual([...remainingCleanupSelection(selected, outcome)], ['C:\\Data\\Two']);
});
