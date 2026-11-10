import ast 

class CallVisitor(ast.NodeVisitor):

    def __init__(self):
        self.calls = []

    def visit_Call(self, node):
        self.calls.append({
            "name": self.get_call_name(node.func),
            "type": type(node.func).__name__,
            "line": node.lineno,
            "args": [ast.unparse(arg) for arg in node.args],
            "keywords": [{key.arg: ast.unparse(key.value)} for key in node.keywords]
        })
        self.generic_visit(node)

    def get_call_name(self, func):
        if isinstance(func, ast.Name):
            return func.id

        else:
            return ast.unparse(func)

class FunctionVisitor(ast.NodeVisitor):
    def __init__(self):
        self.functions = []

    def extract_function(self, node):
        self.functions.append({
            "name": node.name,
            "args": [ast.unparse(arg) for arg in node.args.args],
            "body": {
                "unparsed":ast.unparse(node.body),
                "nodes": node.body
                },
            "decorators": [ast.unparse(decorator) for decorator in node.decorator_list],
            "returns": ast.unparse(node.returns) if node.returns else None,
            "start_line": node.lineno,
            "finish_line": node.end_lineno
        })

    def visit_FunctionDef(self, node):
        self.extract_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.extract_function(node)
        self.generic_visit(node)