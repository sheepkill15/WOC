import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';

const source = await readFile(new URL('../src/scanSync.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { needsScanSync, mergeScanResults } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

test('missed completion and a new externally started scan require synchronization', () => {
  const local = { runId: 1, running: true, resultCount: 2 };
  assert.equal(needsScanSync({ ...local, running: false }, local), true);
  assert.equal(needsScanSync({ ...local, runId: 2 }, local), true);
  assert.equal(needsScanSync(local, local), false);
});

test('missing streamed results require synchronization while the scan runs', () => {
  const local = { runId: 1, running: true, resultCount: 2 };
  assert.equal(needsScanSync({ ...local, resultCount: 3 }, local), true);
});

test('snapshot and replayed events merge without duplicate folder rows', () => {
  const initial = [{ path: 'C:\\Data\\One', sizeBytes: 10 }, { path: 'C:\\Data\\Two', sizeBytes: 5 }];
  const replay = [{ path: 'c:\\data\\one', sizeBytes: 20 }, { path: 'C:\\Data\\Three', sizeBytes: 30 }];
  const merged = mergeScanResults(initial, replay);
  assert.equal(merged.length, 3);
  assert.equal(merged[0].sizeBytes, 20);
  assert.equal(merged[2].sizeBytes, 30);
});
