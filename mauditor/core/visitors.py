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

    @staticmethod
    def get_call_name(func):
        if isinstance(func, ast.Name):
            return func.id

        else:
            return ast.unparse(func)

class FunctionVisitor(ast.NodeVisitor):
    def __init__(self):
        self.functions = []

    def extract_function(self, node, is_async=False):
        posonly_args = node.args.posonlyargs
        positional_args = node.args.args
        defaults = node.args.defaults

        all_positional_args = posonly_args + positional_args
        default_args = all_positional_args[-len(defaults):] if defaults else []

        default_values = {
            arg.arg: ast.unparse(default)
            for arg, default in zip(default_args, defaults)
        }

        default_values_posonly = {
            arg.arg: default_values[arg.arg]
            for arg in posonly_args
            if arg.arg in default_values
        }

        default_values_positional = {
            arg.arg: default_values[arg.arg]
            for arg in positional_args
            if arg.arg in default_values
        }

        kw_args = node.args.kwonlyargs
        defaults_kw = node.args.kw_defaults

        default_values_kw = {
            arg.arg: ast.unparse(default)
            for arg, default in zip(kw_args, defaults_kw)
            if default is not None
        }
        self.functions.append({
            "name": node.name,
            "args": {
                "positional_only": {
                    "args": [ast.unparse(arg) for arg in posonly_args],
                    "default_values": default_values_posonly
                },
                "positional": {
                    "args": [ast.unparse(arg) for arg in positional_args],
                    "default_values": default_values_positional
                },
                "var_positional": ast.unparse(node.args.vararg) if node.args.vararg is not None else None,
                "keyword_only": {
                    "kw_args": [ast.unparse(arg) for arg in kw_args],
                    "default_values": default_values_kw
                },
                "var_keyword": ast.unparse(node.args.kwarg) if node.args.kwarg is not None else None
            },
            "is_async": is_async,
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
        self.extract_function(node, True)
        self.generic_visit(node)

class ImportVisitor(ast.NodeVisitor):
    def __init__(self):
        self.imports = []

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append({
                "module": alias.name,
                "asname": alias.asname,
                "line": node.lineno
            })
        self.generic_visit(node)

class ImportFromVisitor(ast.NodeVisitor):
    def __init__(self):
        self.imports_from = []

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.imports_from.append({
                "module": node.module,
                "name": alias.name,
                "asname": alias.asname,
                "line": node.lineno
            })
        self.generic_visit(node)

class ClassVisitor(ast.NodeVisitor):
    def __init__(self):
        self.classes = []

    def visit_ClassDef(self, node):
        self.classes.append({
            "name": node.name,
            "bases": [ast.unparse(base) for base in node.bases],
            "keywords": [{key.arg: ast.unparse(key.value)} for key in node.keywords],
            "body": {
                "unparsed": ast.unparse(node.body),
                "nodes": node.body
            },
            "decorators": [ast.unparse(decorator) for decorator in node.decorator_list],
            "start_line": node.lineno,
            "finish_line": node.end_lineno
        })
        self.generic_visit(node)

class VariableVisitor(ast.NodeVisitor):
    def __init__(self):
        self.variables = []

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name):
            self.variables.append({
                "name": node.target.id,
                "annotation": ast.unparse(node.annotation),
                "value": ast.unparse(node.value) if node.value else None,
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            self.variables.append({
                "name": node.target.id,
                "operation": type(node.op).__name__,
                "value": ast.unparse(node.value),
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_Global(self, node):
        for name in node.names:
            self.variables.append({
                "name": name,
                "type": "global",
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_Nonlocal(self, node):
        for name in node.names:
            self.variables.append({
                "name": name,
                "type": "nonlocal",
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name):
            self.variables.append({
                "name": f"{node.value.id}.{node.attr}",
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.variables.append({
                    "name": target.id,
                    "value": ast.unparse(node.value),
                    "line": node.lineno
                })
        self.generic_visit(node)