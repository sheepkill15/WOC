import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';
const source = await readFile(new URL('../src/applicationCatalog.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { applicationCatalog, folderBytes, formerOwnerText, resultsAfterCleanup } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
const app = { id: 'one', name: 'Example' };
const other = { id: 'two', name: 'Other' };
const folder = (path, sizeBytes, owner = app, extra = {}) => ({ path, sizeBytes, owner, orphanStatus: 'not_orphaned', ...extra });

test('nested app folders count once regardless of scan parentPath', () => {
  const results = [folder('C:\\Vendor\\Example', 50, app, { parentPath: 'C:\\Vendor' }), folder('C:\\Vendor\\Example\\Cache', 20)];
  const { entries, stray } = applicationCatalog([app], results);
  assert.equal(entries[0].bytes, 50);
  assert.equal(entries[0].folders.length, 2);
  assert.equal(stray.length, 0);
  assert.equal(folderBytes(results), 50);
});
test('ownership partitions exclude other owners and preserve same-owner grandchildren', () => {
  const results = [folder('C:\\Root', 100), folder('C:\\Root\\Other', 40, other), folder('C:\\Root\\Other\\Example', 10)];
  const { entries } = applicationCatalog([app, other], results);
  assert.equal(entries[0].bytes, 70);
  assert.equal(entries[1].bytes, 30);
});
test('former app data stays stray even if an older version owner has the same installed name', () => {
  const old = folder('C:\\Old', 10, app, { orphanStatus: 'possibly_orphaned' });
  const { entries, stray } = applicationCatalog([app], [old]);
  assert.equal(entries[0].folders.length, 0);
  assert.equal(stray.length, 1);
  assert.match(formerOwnerText(old), /Example/);
});
test('missing registrations, shared folders and unknown data are stray; duplicate paths do not double-count', () => {
  const results = [folder('C:\\Example', 10), folder('c:/example/', 20), folder('C:\\Other', 40, other), folder('C:\\Shared', 15, app, { ownership: 'shared' }), folder('C:\\Unknown', 5, null)];
  const { entries, stray } = applicationCatalog([app], results);
  assert.equal(entries[0].bytes, 20);
  assert.equal(stray.length, 3);
});
test('cleanup updates ancestor sizes and preserves failed moves', () => {
  const results = [folder('C:\\Root', 100), folder('C:\\Root\\Cache', 30), folder('C:\\Root\\Other', 20)];
  const updated = resultsAfterCleanup(results, [{ path: 'c:/root/cache', sizeBytes: 30, moved: true }, { path: 'C:\\Root\\Other', sizeBytes: 20, moved: false }]);
  assert.equal(updated.length, 2);
  assert.equal(updated[0].sizeBytes, 70);
  assert.equal(applicationCatalog([app], updated).entries[0].bytes, 70);
});
test('duplicate package families create one application entry', () => {
  assert.equal(applicationCatalog([app, app], []).entries.length, 1);
});

test('shared associations appear under every current app without multiplying totals', () => {
  const shared = folder('C:\\NVIDIA', 100, null, { ownership: 'shared', orphanStatus: 'associated_with_installed', associatedApplications: [app, other, app] });
  const child = folder('C:\\NVIDIA\\Example', 30);
  const nested = folder('C:\\NVIDIA\\Shared', 20, null, { ownership: 'shared', orphanStatus: 'associated_with_installed', associatedApplications: [app, other] });
  const { entries, stray, sharedBytes } = applicationCatalog([app, other], [shared, child, nested]);
  assert.deepEqual(entries.map(entry => entry.sharedFolders.length), [2, 2]);
  assert.deepEqual(entries.map(entry => entry.bytes), [30, 0]);
  assert.equal(sharedBytes, 70);
  assert.equal(stray.length, 0);
});

test('stale shared associations cannot absorb unknown, former, missing-app or manually owned folders', () => {
  const extra = { ownership: 'shared', orphanStatus: 'associated_with_installed', associatedApplications: [other] };
  const missing = folder('C:\\Missing', 10, null, extra);
  const former = folder('C:\\Former', 20, null, { ...extra, associatedApplications: [app], orphanStatus: 'possibly_orphaned' });
  const unknown = folder('C:\\Unknown', 30, null, { ...extra, associatedApplications: [app], ownership: 'unknown' });
  const manual = folder('C:\\Manual', 40, app, { ...extra, ownership: 'manual', orphanStatus: 'not_orphaned' });
  const { entries, stray, sharedBytes } = applicationCatalog([app], [missing, former, unknown, manual]);
  assert.equal(entries[0].sharedFolders.length, 0);
  assert.equal(entries[0].bytes, 40);
  assert.equal(sharedBytes, 0);
  assert.equal(stray.length, 3);
});
