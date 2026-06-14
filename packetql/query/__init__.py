"""Query layer: a SQL-like read-only query engine over the columnar packet store.

Lexer + recursive-descent parser reuse QueryX's design; the executor is new —
it runs over the columnar store and reads only the columns a query references.
"""
