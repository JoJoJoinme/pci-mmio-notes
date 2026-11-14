"""Deterministic display of extracted facts; no binary reads or mutations."""
import json,re

def short_symbol(name):
    original=name
    if name.startswith('_ZNK'):rest=name[4:]
    elif name.startswith('_ZN'):rest=name[3:]
    else:return name
    parts=[]
    while rest and rest[0].isdigit():
        m=re.match(r'(\d+)',rest);n=int(m[1]);rest=rest[len(m[1]):]
        if len(rest)<n:break
        parts.append(rest[:n]);rest=rest[n:]
    return '::'.join(parts[-2:]) if parts else original

def reference_text(ref):
    kind=ref['kind']
    if kind=='relocation':
        name=ref['symbol'] or ('section#'+str(ref['symbolSection']))
        text='REL type='+str(ref['type'])+' '+short_symbol(name)+' A='+str(ref['addend'])
        if 'literal' in ref:text+=' '+json.dumps(ref['literal']['text'],ensure_ascii=False)
        return text
    if kind=='plt':return 'PLT -> '+short_symbol(ref['symbol'])
    if kind=='got':return 'GOT -> '+short_symbol(ref['symbol'])
    if kind in ['directSymbol','ripSymbol']:return kind+' -> '+' | '.join(short_symbol(x) for x in ref['symbols'])
    if kind=='objectInterior':return ref['symbol']+'+'+ref['offset']
    if kind=='literal':return 'literal '+json.dumps(ref['text'],ensure_ascii=False)
    return kind

def code(s):
    rows=[]
    for r in s['instructions']:
        raw=' '.join(r['bytes'][i:i+2] for i in range(0,len(r['bytes']),2))
        line=f"{r['address']:>18} (+{int(r['functionOffset'],16):04x})  {raw:<44}  {r['mnemonic']:<7} {r['operands']}"
        notes=[reference_text(x) for x in r['references']]
        if r['branch'] and not r['branch']['insideWindow']:notes.append('branch leaves this window')
        if notes:line+=' ; '+'; '.join(notes)
        rows.append(line.rstrip())
    return '\n'.join(rows)+'\n'

def markdown(s,images):
    meta=images[s['image']]
    head=f"<!-- evidence:{s['id']}:begin -->\n\n### 切片 {s['id']} {s['title']}\n\n"
    head+=f"- 文件：`{meta['component']}`，build `{meta['build']}`；地址类型：{s['addressKind']}。\n"
    head+=f"- 函数：`{s['functionLabel']}`；入口 `{s['functionAddress']}`，函数大小 `{s['functionBytes']}` 字节。\n"
    if s.get('symbol','') and s['symbol'].startswith('_Z'):head+=f"- 原始符号：`{s['symbol']}`。\n"
    head+=f"- 窗口：`{s['startAddress']}` 到 `{s['endAddressExclusive']}`（右端不含）；文件偏移 `{s['startFileOffset']}`；{s['instructionCount']} 条指令。\n"
    head+=f"- 窗口 SHA-256：`{s['windowSha256']}`。[单独查看汇编](snippets/{s['id']}.asm)\n\n"
    return head+'```asm\n'+code(s)+'```\n\n<!-- evidence:'+s['id']+':end -->'
