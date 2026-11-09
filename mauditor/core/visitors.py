import ast 



class CallVisitor(ast.NodeVisitor):

    def __init__(self):
        self.calls = []

    def visit_Call(self, node):
        self.calls.append({
            "name": node.func.id if isinstance(node.func, ast.Name) else node.func.attr,
            "type": type(node.func).__name__,
            "line": node.lineno,
            "args": [ast.unparse(arg) for arg in node.args],
            "keywords": [{key.arg: ast.unparse(key.value)} for key in node.keywords]
        })
        self.generic_visit(node)