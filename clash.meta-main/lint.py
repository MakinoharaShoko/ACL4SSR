#!/usr/bin/env python3
# /// script
# dependencies = ["ruamel.yaml>=0.18"]
# ///
"""
Clash config formatter.

Features:
* Collapse anchor definitions (pp/pg/rp) to single-line flow mappings.
* Emit proxy-providers, proxy-groups, and rule-providers entries as single-line flow mappings.
* Align comma positions within each logical block of rules entries.
* Trim trailing whitespace and replace tabs with two spaces.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def strip_trailing_whitespace(lines: List[str]) -> List[str]:
    return [line.rstrip().replace("\t", "  ") for line in lines]


def find_block(lines: List[str], start: int) -> Tuple[int, int]:
    """Return [start, end) slice covering the logical block beginning at start."""
    indent = indent_of(lines[start])
    end = start + 1
    while end < len(lines):
        stripped = lines[end].strip()
        if stripped == "":
            end += 1
            continue
        if indent_of(lines[end]) <= indent and not stripped.startswith("#"):
            break
        end += 1
    return start, end


def format_scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if value is None:
        return "null"
    s = str(value)
    if any(c in s for c in ",[]{}&*#?|<>") or ": " in s or s.startswith(("!", "-", ":")) or s == "":
        return json.dumps(s, ensure_ascii=False)
    return s


def format_seq(seq) -> str:
    return "[" + ", ".join(format_value(item) for item in seq) + "]"


def format_map(map_obj: CommentedMap) -> str:
    parts = []
    merges = getattr(map_obj, "merge", None)
    if merges:
        for merge_item in merges:
            anchor = getattr(getattr(merge_item, "anchor", None), "value", None)
            if anchor:
                parts.append(f"<<: *{anchor}")
            else:
                parts.append(f"<<: {format_value(merge_item)}")
    items_iter = (
        map_obj.non_merged_items()
        if hasattr(map_obj, "non_merged_items")
        else map_obj.items()
    )
    for key, value in items_iter:
        parts.append(f"{key}: {format_value(value)}")
    return "{ " + ", ".join(parts) + " }"


def format_value(value) -> str:
    if isinstance(value, CommentedMap):
        return format_map(value)
    if isinstance(value, CommentedSeq):
        return format_seq(value)
    if isinstance(value, list):
        return "[" + ", ".join(format_value(v) for v in value) + "]"
    return format_scalar(value)


def collapse_anchor(lines: List[str], data, key: str) -> None:
    for idx, line in enumerate(lines):
        if line.strip().startswith(f"{key}:"):
            block_start, block_end = find_block(lines, idx)
            anchor_map = data.get(key)
            if not isinstance(anchor_map, CommentedMap):
                return
            anchor = getattr(getattr(anchor_map, "anchor", None), "value", None)
            if not anchor:
                return
            inner = ", ".join(f"{k}: {format_value(v)}" for k, v in anchor_map.items())
            indent = " " * indent_of(line)
            replacement = f"{indent}{key}: &{anchor} {{ {inner} }}"
            lines[block_start:block_end] = [replacement]
            return


def align_flow_maps(raw_lines: List[str]) -> List[str]:
    """Align { , } vertically within a group of flow-map lines."""
    if not raw_lines:
        return raw_lines
    
    # Find max prefix length (before {)
    max_prefix = max(line.index('{') for line in raw_lines)
    
    parsed = []
    for line in raw_lines:
        prefix = line[:line.index('{')]
        content = line[line.index('{'):]
        parts = content.split(',')
        parsed.append((prefix, parts))
    
    max_positions = [0] * max(len(parts) for _, parts in parsed)
    
    for prefix, parts in parsed:
        current_pos = max_prefix  # Start from aligned {
        for i, part in enumerate(parts):
            current_pos += len(part)
            if i < len(max_positions):
                max_positions[i] = max(max_positions[i], current_pos)
            if i < len(parts) - 1:
                current_pos += 1
    
    aligned = []
    for prefix, parts in parsed:
        result = prefix.ljust(max_prefix)  # Pad prefix to align {
        current_pos = max_prefix
        for i, part in enumerate(parts):
            result += part
            current_pos += len(part)
            if i < len(parts) - 1:
                padding = max_positions[i] - current_pos
                result += ' ' * padding + ','
                current_pos = max_positions[i] + 1
        aligned.append(result)
    
    return aligned


def collapse_mapping_section(lines: List[str], data, section: str) -> None:
    for idx, line in enumerate(lines):
        if line.strip().startswith(f"{section}:"):
            block_start, block_end = find_block(lines, idx)
            section_map = data.get(section)
            if not isinstance(section_map, CommentedMap):
                return
            entry_indent = " " * (indent_of(line) + 2)
            had_blank = block_end > idx + 1 and lines[block_end - 1].strip() == ""
            raw_lines = [
                f"{entry_indent}{name}: {format_value(value)}"
                for name, value in section_map.items()
            ]
            new_lines = align_flow_maps(raw_lines)
            if had_blank:
                new_lines.append("")
            lines[idx + 1 : block_end] = new_lines
            return


def collapse_proxy_groups(lines: List[str], data) -> None:
    section = "proxy-groups"
    for idx, line in enumerate(lines):
        if line.strip().startswith(f"{section}:"):
            block_start, block_end = find_block(lines, idx)
            groups = data.get(section)
            if not isinstance(groups, CommentedSeq):
                return
            entry_indent = " " * (indent_of(line) + 2)
            had_blank = block_end > idx + 1 and lines[block_end - 1].strip() == ""
            raw_lines = []
            for item in groups:
                if not isinstance(item, CommentedMap):
                    continue
                parts = []
                merges = getattr(item, "merge", None)
                if merges:
                    for merge_item in merges:
                        anchor = getattr(
                            getattr(merge_item, "anchor", None), "value", None
                        )
                        if anchor:
                            parts.append(f"<<: *{anchor}")
                        else:
                            parts.append(f"<<: {format_value(merge_item)}")
                items_iter = (
                    item.non_merged_items()
                    if hasattr(item, "non_merged_items")
                    else item.items()
                )
                for key, value in items_iter:
                    parts.append(f"{key}: {format_value(value)}")
                raw_lines.append(f"{entry_indent}- {{ {', '.join(parts)} }}")
            new_lines = align_flow_maps(raw_lines)
            if had_blank:
                new_lines.append("")
            lines[idx + 1 : block_end] = new_lines
            return


def align_rules(lines: List[str]) -> None:
    section = "rules"
    start_idx = None
    for idx, line in enumerate(lines):
        if line.strip().startswith(f"{section}:"):
            start_idx = idx
            break
    if start_idx is None:
        return
    _, block_end = find_block(lines, start_idx)

    block_entries: List[Tuple[int, List[str]]] = []

    def flush() -> None:
        nonlocal block_entries
        if not block_entries:
            return
        # Find max parts count
        max_parts = max(len(parts) for _, parts in block_entries)
        # Calculate max length for each part
        max_lens = [0] * max_parts
        for _, parts in block_entries:
            for i, part in enumerate(parts):
                max_lens[i] = max(max_lens[i], len(part))
        
        # Rebuild lines with aligned commas
        for idx, parts in block_entries:
            indent = " " * indent_of(lines[idx])
            aligned_parts = []
            for i, part in enumerate(parts):
                if i < len(parts) - 1:
                    aligned_parts.append(part.ljust(max_lens[i]))
                else:
                    aligned_parts.append(part)  # Last part no padding
            lines[idx] = f"{indent}- {','.join(aligned_parts)}"
        block_entries = []

    for idx in range(start_idx + 1, block_end):
        line = lines[idx]
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or not stripped.startswith("- "):
            flush()
            continue
        content = stripped[2:]
        if "," not in content:
            flush()
            continue
        parts = [p.strip() for p in content.split(",")]
        block_entries.append((idx, parts))
    flush()


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: lint.py <config.yaml>", file=sys.stderr)
        sys.exit(1)
    path = Path(sys.argv[1])
    text = path.read_text()
    lines = strip_trailing_whitespace(text.splitlines())

    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    data = yaml.load(text)

    for key in ("pp", "pg", "rp"):
        collapse_anchor(lines, data, key)

    collapse_mapping_section(lines, data, "proxy-providers")
    collapse_mapping_section(lines, data, "rule-providers")
    collapse_proxy_groups(lines, data)
    align_rules(lines)

    result = "\n".join(lines) + "\n"
    sys.stdout.write(result)


if __name__ == "__main__":
    main()
