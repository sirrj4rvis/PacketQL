"""Index layer: data structures that accelerate queries (the DSA core).

- HashIndex    - O(1) equality lookups          (e.g. dst_port = 443)
- IPTrie       - O(k) IP prefix/subnet lookups   (e.g. src_ip LIKE '10.0.5.%')
- BoundedTopN  - heap-based ORDER BY ... LIMIT N  (no full sort)
"""
