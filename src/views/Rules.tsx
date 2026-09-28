import { useState } from "react";
import { useCleaner } from "../store";
import { categoryOptions, formatDate, kindLabels } from "../format";
import type { IgnoreRule } from "../types";
import { Empty, Icon, PageHeader, Section } from "../ui";

const kindText: Record<IgnoreRule["kind"], { title: string; description: string }> = {
  path: { title: "Always ignore these folders", description: "The folder and everything inside it are never offered for cleanup." },
  application: { title: "Always keep these applications", description: "Leftover and cache groups for these owners are kept aside." },
  category: { title: "Always keep these types of data", description: "Subfolders of these types are never selectable, and folders containing them cannot be removed whole." },
  once: { title: "Hidden until the next scan", description: "Hidden only while the current scan is shown." },
};

export function Rules() {
  const { rules, addRule, removeRule, backend } = useCleaner();
  const [path, setPath] = useState("");
  const [category, setCategory] = useState(categoryOptions[0]);
  const connected = backend === "tauri" || backend === "agent";
  const keptCategories = new Set(rules.filter(rule => rule.kind === "category").map(rule => rule.value));

  return <div className="page">
    <PageHeader title="Ignore rules" description="Tell the cleaner what you intend to keep, so it stops asking." />
    <div className="rule-forms">
      <form className="card" onSubmit={event => { event.preventDefault(); if (path.trim()) { void addRule("path", path.trim(), path.trim()); setPath(""); } }}>
        <h3>Ignore a folder</h3>
        <p className="muted small">Paste a full path, for example a game or plug-in folder you keep on purpose.</p>
        <div className="inline-form"><input value={path} onChange={event => setPath(event.target.value)} placeholder="C:\Users\you\AppData\Roaming\MyTool" aria-label="Folder path" /><button className="secondary" disabled={!connected || !path.trim()}>Add</button></div>
      </form>
      <form className="card" onSubmit={event => { event.preventDefault(); void addRule("category", category, kindLabels[category] ?? category); }}>
        <h3>Keep a type of data</h3>
        <p className="muted small">Save games, projects, documents and media are already classified “Preserve”; a rule also makes them unselectable.</p>
        <div className="inline-form">
          <select value={category} onChange={event => setCategory(event.target.value)} aria-label="Data type">
            {categoryOptions.map(option => <option key={option} value={option} disabled={keptCategories.has(option)}>{kindLabels[option] ?? option}</option>)}
          </select>
          <button className="secondary" disabled={!connected || keptCategories.has(category)}>Keep</button>
        </div>
      </form>
    </div>
    {rules.length === 0 && <Empty icon="rules" title="No rules yet">Use “Ignore…” on any folder or “Always keep” on a cleanup group to add one.</Empty>}
    {(["application", "path", "category", "once"] as const).map(kind => {
      const list = rules.filter(rule => rule.kind === kind);
      if (!list.length) return null;
      return <Section key={kind} title={kindText[kind].title} description={kindText[kind].description}>
        <ul className="rule-list">{list.map(rule => <li key={rule.id}>
          <div><strong title={rule.value}>{rule.label}</strong>{rule.label !== rule.value && <span title={rule.value}>{rule.value}</span>}<small>Added {formatDate(rule.createdAtUnix)}</small></div>
          <button className="ghost" onClick={() => void removeRule(rule.id)}><Icon name="close" size={14} /> Remove</button>
        </li>)}</ul>
      </Section>;
    })}
  </div>;
}
