"""只读 Mach-O 段/节与 ar 成员摘要，解释重建差异，不改二进制。"""

import hashlib
import struct


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sections(path):
    data = path.read_bytes()
    magic, _, _, _, count, _, _, _ = struct.unpack_from('<8I', data)
    assert magic == 0xfeedfacf, '只支持本项64位小端 Mach-O'
    offset, result = 32, {}
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, offset)
        assert size >= 8 and offset + size <= len(data)
        if command == 0x19:
            number = struct.unpack_from('<I', data, offset + 64)[0]
            for i in range(number):
                record = offset + 72 + i * 80
                name, segment, _, length, start = struct.unpack_from('<16s16sQQI', data, record)
                key = segment.rstrip(b'\0').decode() + '/' + name.rstrip(b'\0').decode()
                result[key] = {'size': length, 'offset': start,
                               'sha256': digest(data[start:start + length]) if start else None}
        offset += size
    return result


def compare(original, rebuilt):
    a, b = sections(original), sections(rebuilt)
    differences = [{'name': key, 'original': a.get(key), 'rebuilt': b.get(key)}
                   for key in sorted(a.keys() | b.keys()) if a.get(key) != b.get(key)]
    texts = []
    for path, values in [(original, a), (rebuilt, b)]:
        section = values['__TEXT/__cstring']
        data = path.read_bytes()[section['offset']:section['offset'] + section['size']]
        texts.append(set(data.split(b'\0')))
    return {'unsigned_bytes_equal': original.read_bytes() == rebuilt.read_bytes(),
            'section_differences': differences,
            'original_only_cstrings': [s.decode(errors='replace') for s in sorted(texts[0] - texts[1])],
            'rebuilt_only_cstrings': [s.decode(errors='replace') for s in sorted(texts[1] - texts[0])]}


def ar_members(path):
    data = path.read_bytes()
    assert data[:8] == b'!<arch>\n', '不是 ar 归档'
    offset, result, longnames = 8, [], b''
    while offset < len(data):
        header = data[offset:offset + 60]
        assert len(header) == 60 and header[58:] == b'`\n'
        name = header[:16].decode().strip()
        size = int(header[48:58])
        body = data[offset + 60:offset + 60 + size]
        assert len(body) == size
        if name.startswith('#1/'):
            length = int(name[3:])
            name, body = body[:length].rstrip(b'\0').decode(), body[length:]
        elif name == '//':
            longnames = body
        elif name.startswith('/') and name[1:].isdigit():
            name = longnames[int(name[1:]):].split(b'/\n')[0].decode()
        else:
            name = name.rstrip('/')
        if name and name not in ['/', '//'] and not name.startswith('__.SYMDEF'):
            result.append({'name': name, 'size': len(body), 'sha256': digest(body)})
        offset += 60 + size + size % 2
    assert offset == len(data)
    return result
