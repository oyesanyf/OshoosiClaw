import re
import sys

def main():
    with open('README.md', 'r', encoding='utf-8') as f:
        content = f.read()

    # Find all hrefs
    hrefs = re.findall(r'href=["\'](#[^"\']+)["\']', content)
    md_links = re.findall(r'\[([^\]]+)\]\((#[^)]+)\)', content)

    all_anchors = hrefs + [m[1] for m in md_links]

    # Find all ids
    ids = set(re.findall(r'id=["\']([^"\']+)["\']', content))

    # Find all headings and compute standard github anchors
    headings = re.findall(r'^(#{1,6})\s+(.+)$', content, re.MULTILINE)
    github_anchors = set()
    for level, h in headings:
        # clean heading text
        slug = h.lower()
        # remove HTML tags
        slug = re.sub(r'<[^>]+>', '', slug)
        # remove punctuation except hyphens and spaces
        slug = re.sub(r'[^\w\s-]', '', slug)
        # replace spaces with hyphens
        slug = re.sub(r'\s+', '-', slug.strip())
        github_anchors.add(slug)
        github_anchors.add('-' + slug)

    print(f"Total internal links found: {len(all_anchors)}")
    missing = []
    for a in sorted(set(all_anchors)):
        target = a[1:]  # remove #
        target_clean = target.lstrip('-')
        matched = False
        if target in ids:
            matched = True
            print(f"  {a}: MATCHED (id tag: <a id='{target}'>)")
        elif target in github_anchors:
            matched = True
            print(f"  {a}: MATCHED (heading slug: {target})")
        elif target_clean in github_anchors:
            matched = True
            print(f"  {a}: MATCHED (heading slug: {target_clean})")
        else:
            missing.append(a)
            print(f"  {a}: *** MISSING ***")

    # Check code fences
    fence_count = len(re.findall(r'^```', content, re.MULTILINE))
    print(f"\nCode fences count: {fence_count} (even={fence_count % 2 == 0})")

    # Check tables
    lines = content.splitlines()
    table_errors = []
    in_table = False
    expected_cols = 0
    table_start_line = 0

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('|') and stripped.endswith('|'):
            # Split ignoring escaped pipes \|
            cols = len([c for c in re.split(r'(?<!\\)\|', stripped)[1:-1]])
            if not in_table:
                in_table = True
                expected_cols = cols
                table_start_line = idx
            else:
                if cols != expected_cols:
                    table_errors.append(f"Line {idx} has {cols} columns, expected {expected_cols} (table started at {table_start_line})")
        else:
            in_table = False

    print(f"Table errors: {len(table_errors)}")
    for err in table_errors:
        print(f"  {err}")

    # Remove code blocks and inline code spans before checking HTML tags
    cleaned_content = re.sub(r'```.*?```', '', content, flags=re.DOTALL)
    cleaned_content = re.sub(r'`[^`\n]+`', '', cleaned_content)

    # Check unclosed HTML tags
    open_tags = re.findall(r'<([a-zA-Z0-9]+)(?:\s+[^>]*?)?(?<!/)>', cleaned_content)
    close_tags = re.findall(r'</([a-zA-Z0-9]+)>', cleaned_content)
    void_tags = {'img', 'br', 'hr', 'input', 'meta', 'link'}
    filtered_open = [t.lower() for t in open_tags if t.lower() not in void_tags]
    filtered_close = [t.lower() for t in close_tags]

    from collections import Counter
    open_counts = Counter(filtered_open)
    close_counts = Counter(filtered_close)

    print("\nHTML tag balance (excluding code blocks/spans):")
    html_mismatches = []
    for tag in set(filtered_open + filtered_close):
        o = open_counts.get(tag, 0)
        c = close_counts.get(tag, 0)
        if o != c:
            html_mismatches.append(f"Tag <{tag}> mismatch: opened {o}, closed {c}")
            print(f"  *** Tag <{tag}> mismatch: opened {o}, closed {c}")
        else:
            print(f"  Tag <{tag}>: balanced ({o})")

    if missing or table_errors or html_mismatches or (fence_count % 2 != 0):
        print("\nVerification found issues!")
        return 1
    else:
        print("\nAll checks passed cleanly!")
        return 0

if __name__ == '__main__':
    sys.exit(main())
