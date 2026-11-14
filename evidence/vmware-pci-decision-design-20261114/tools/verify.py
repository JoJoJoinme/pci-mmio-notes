"""Read-only document consistency checks. This does not test VMware behavior."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    manifest = read_json(ROOT / "manifest.json")
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
              if p.is_file() and p.name != "manifest.json"}
    listed = {f["path"] for f in manifest["files"]}
    assert actual == listed, (actual - listed, listed - actual)
    for entry in manifest["files"]:
        data = (ROOT / entry["path"]).read_bytes()
        assert len(data) == entry["bytes"], entry["path"]
        assert sha(data) == entry["sha256"], entry["path"]

    evidence = read_json(ROOT / "evidence-map.json")
    for entry in evidence["sources"]:
        source = REPO / entry["path"]
        assert sha(source.read_bytes()) == entry["sha256"], entry["path"]
        pinned = subprocess.check_output(
            ["git", "show", f'{evidence["sourceRevision"]}:{entry["path"]}'], cwd=REPO)
        assert sha(pinned) == entry["sha256"], entry["path"]
    snippets = read_json(REPO / evidence["snippetIndex"])
    known = {entry["id"]: entry for entry in snippets["snippets"]}
    sys.path.insert(0, str(ROOT.parent / 'vmware-pci-assembly-dossier-20261114/tools'))
    from evidence_format import code, markdown
    supplement_count = 0
    for relative in [evidence['localSupplement']] + evidence.get('additionalSupplements', []):
        supplement_path = ROOT / relative
        supplement = read_json(supplement_path)
        folder = supplement_path.parent
        supplement_proof = read_json(folder / 'objdump-verification.json')
        assert supplement_proof['status'] == 'PASS'
        assert supplement_proof['sourceSnippetsSha256'] == sha(supplement_path.read_bytes())
        assert supplement_proof['windows'] == len(supplement['snippets'])
        assert supplement_proof['instructionsCompared'] == sum(s['instructionCount'] for s in supplement['snippets'])
        displayed = (folder / 'README.md').read_text(encoding='utf-8')
        for selected in supplement['snippets']:
            assert selected['id'] not in known
            known[selected['id']] = selected
            raw = bytes.fromhex(''.join(i['bytes'] for i in selected['instructions']))
            assert sha(raw) == selected['windowSha256']
            assert (folder / 'snippets' / (selected['id'] + '.asm')).read_text(encoding='utf-8').endswith(code(selected))
            assert markdown(selected, supplement['images']) in displayed
            supplement_count += 1
    for entry in evidence["nodes"]:
        assert entry["node"] in (ROOT / entry["diagram"]).read_text(encoding="utf-8")
        for selected in entry["snippets"]:
            original = known[selected["id"]]
            assert selected["windowSha256"] == original["windowSha256"]
            assert selected["startAddress"] == original["startAddress"]

    renders = read_json(ROOT / "render-receipt.json")
    assert not renders["pageErrors"]
    for diagram in renders["diagrams"]:
        stem = diagram["stem"]
        for ext, key in [("mmd", "sourceSha256"), ("svg", "svgSha256"), ("png", "pngSha256")]:
            assert sha((ROOT / "diagrams" / f"{stem}.{ext}").read_bytes()) == diagram[key]
        tree = ET.parse(ROOT / "diagrams" / f"{stem}.svg")
        assert all(not node.tag.endswith("foreignObject") for node in tree.iter())
        source = (ROOT / "diagrams" / f"{stem}.mmd").read_text(encoding="utf-8")
        ids = re.search(r"^%% evidence: (.+)$", source, re.M).group(1).split()
        assert all(key in known for key in ids)

    link_count = 0
    for doc in ROOT.rglob("*.md"):
        text = doc.read_text(encoding="utf-8")
        for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text):
            if "://" in target:
                continue
            file, _, anchor = target.partition("#")
            resolved = (doc.parent / file).resolve() if file else doc
            assert resolved.is_file(), target
            if anchor:
                content = resolved.read_text(encoding="utf-8")
                assert f'id="{anchor}"' in content, target
            link_count += 1
    print(json.dumps({"result": "PASS", "scope": "Document and evidence consistency only",
                      "manifestFiles": len(listed), "pinnedSources": len(evidence["sources"]),
                      "mappedNodes": len(evidence["nodes"]), "renderedDiagrams": len(renders["diagrams"]),
                      "supplementWindows": supplement_count, "localLinks": link_count}, ensure_ascii=False))


if __name__ == "__main__":
    main()
