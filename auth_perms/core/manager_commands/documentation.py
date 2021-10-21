import os
import ast
import tokenize
import re


class BuildDocumentationMixIn:

    @staticmethod
    def build_documentation(content):
        result = []
        root_files = content
        for file in root_files:
            branch = '├' if file is not root_files[-1] else '└'
            if isinstance(file, Module):
                result.append(f'\t{branch} {file.name}')
            else:
                result.append(f'\t{branch} {file.name}')
                for line in file.build_documentation(file.content):
                    if file is not root_files[-1]:
                        result.append('\t' + '|' + line)
                    else:
                        result.append('\t' + line)

        return result


class ServiceDocumentation(BuildDocumentationMixIn):
    """
    Class representing whole documentation
    for service.
    """

    def __init__(self, service_path):
        self.service_path = os.path.abspath(service_path)
        self.service_name = self.service_path.split(os.sep)[-1]
        self.content = self.build_tree()

    def build_tree(self):
        ignore = ['env', 'venv', '.git', 'static', 'templates', '__pycache__', '.idea', 'docs']

        documentation_tree = []
        if os.path.isdir(self.service_path):
            listdir = [file for file in os.listdir(self.service_path) if file not in ignore]
            for file in listdir:
                path = os.path.join(self.service_path, file)
                if os.path.isdir(path):
                    documentation_tree.append(Directory(path))
                elif file.split('.')[-1] == 'py':
                    documentation_tree.append(Module(path))
                else:
                    continue
        else:
            raise NotADirectoryError(f'{self.service_path} is not a directory!')

        documentation_tree.sort(key=lambda x: isinstance(x, Directory), reverse=True)

        return documentation_tree


class File:

    def __init__(self, path, parent=None):
        self.path = path
        self.name = self.get_name()
        self.parent = parent
        self._ignore = ['env', 'venv', '.git', 'static', 'templates', '__pycache__', '.idea', 'docs', '__init__.py']

    def get_name(self):
        return self.path.split('/')[-1]

    def __repr__(self):
        return self.name


class Directory(File, BuildDocumentationMixIn):

    def __init__(self, path, parent=None):
        super().__init__(path, parent)
        self.content = self._get_content()
        self.flows_tree = self.build_flows_tree()

    def _get_content(self):
        directories = []
        listdir = [file for file in os.listdir(self.path) if file not in self._ignore]
        for file in listdir:
            path = os.path.join(self.path, file)
            if os.path.isdir(path):
                directories.append(Directory(path, self))
            elif file.split('.')[-1] == 'py':
                directories.append(Module(path, self))
            else:
                continue
        return directories

    def build_flows_tree(self):
        # Get directory modules
        modules = [file for file in self.content if isinstance(file, Module)]

        groups, flow_defs, flow_boxes = [], [], []
        for module in modules:
            groups.extend(module.group_defs)
            flow_defs.extend(module.flow_defs)
            flow_boxes.extend(module.flow_boxes)
        groups.sort(key=lambda x: x.description)

        # Set relations for flow boxes
        for flow_box in flow_boxes:
            if not flow_box.relations_str:
                continue
            relations = flow_box.relations_str.split(',')
            for relation in relations:
                arrow_text = ''
                arrow_pattern = re.search(r'\|(.*)\|\d{2}-\d{2}', relation)
                if arrow_pattern:
                    arrow_text = arrow_pattern.group(1)
                    relation = relation.replace(f'|{arrow_text}|', '')
                item, number = relation.split('-')
                if '|' in item or '|' in number:
                    breakpoint()
                item, number = int(item), int(number)
                relation_obj = list(filter(lambda x: x.id == item and x.number == number, flow_boxes))
                if len(relation_obj) > 1:
                    flow_box.relations.append((arrow_text, relation_obj[0]))
                    continue
                try:
                    flow_box.relations.append((arrow_text, relation_obj[0]))
                except IndexError:
                    raise SyntaxError(f'Relation {relation} for flow box '
                                      f'{flow_box.id}-{flow_box.number} {flow_box.description} don\'t exists')

        # Set flow boxes for flow_def
        for flow_def in flow_defs:
            flow_def.flow_boxes.extend([flow_box for flow_box in flow_boxes if flow_box.id == flow_def.id])
            flow_def.flow_boxes.sort(key=lambda x: x.number)

        for group in groups:
            group.flow_defs.extend(flow_def for flow_def in flow_defs if flow_def.id in group.id)
            group.flow_defs.sort(key=lambda x: x.id)

        return groups


class Module(File):

    def __init__(self, path, parent=None):
        super().__init__(path, parent)
        self.group_defs = []
        self.flow_defs = []
        self.flow_boxes = []
        self.classes, self.functions = self._parse_file()
        self.get_flow_boxes()

    def _parse_file(self):
        with open(self.path) as f:
            file_module = ast.parse(f.read())
            classes = [Class(node, self) for node in file_module.body if isinstance(node, ast.ClassDef)]
            functions = [Function(node, self) for node in file_module.body if isinstance(node, ast.FunctionDef)]
            return classes, functions

    def get_groups_and_flows(self, docstring):
        # Get groups from docstring
        group = re.search(r':group:\s*\((.*)\)\s*\"(.*)\"', docstring)
        while group:
            flow_ids = [int(flow_id) for flow_id in group.group(1).split(',')]
            group_name = group.group(2)
            self.group_defs.append(Group(group_name, flow_ids))
            docstring = docstring.replace(group.group(0), '')
            group = re.search(r':group:\s*\((.*)\)\s*\"(.*)\"', docstring)

        # Get flow definitions from docstring
        flow_def = re.search(r':flow:\s*(\d{2})\s*\"(.*)\"', docstring)
        while flow_def:
            flow_item = int(flow_def.group(1))
            flow_description = flow_def.group(2)
            self.flow_defs.append(FlowDef(flow_description, flow_item))
            docstring = docstring.replace(flow_def.group(0), '')
            flow_def = re.search(r':flow:\s*(\d{2})\s*\"(.*)\"', docstring)

        # Get flow boxes from docstring
        flow_box = re.search(r':flow:\s*(\d{2})-(\d{2})(\?)?(\((|.*|\d{2}-\d{2})\))?\s*\"(.*)\"', docstring)
        while flow_box:
            item = int(flow_box.group(1))
            number = int(flow_box.group(2))
            decision = True if flow_box.group(3) == '?' else False
            relations_str = flow_box.group(5) if flow_box.group(5) else ''
            description = flow_box.group(6)
            self.flow_boxes.append(FlowBox(description, item, number, relations_str, decision))
            docstring = docstring.replace(flow_box.group(0), '')
            flow_box = re.search(r':flow:\s*(\d{2})-(\d{2})(\?)?(\((|.*|\d{2}-\d{2})\))?\s*\"(.*)\"', docstring)

        return docstring

    def get_flow_boxes(self):
        with open(self.path) as module:
            # Get all comments from module
            comments = [token[1] for token in tokenize.generate_tokens(module.readline) if token[0] == 55]

        for comment in comments:
            flow_box = re.search(r':flow:\s*(\d{2})-(\d{2})(\?)?(\((|.*|\d{2}-\d{2})\))?\s*\"(.*)\"', comment)
            if flow_box:
                item = int(flow_box.group(1))
                number = int(flow_box.group(2))
                decision = True if flow_box.group(3) == '?' else False
                relations_str = flow_box.group(5) if flow_box.group(5) else ''
                description = flow_box.group(6)
                self.flow_boxes.append(FlowBox(description, item, number, relations_str, decision))


class PyObjectBase:

    def __init__(self, node, parent):
        self.name = node.name
        self.parent = parent
        self.docstring = self._get_docstring(node)

    def __repr__(self):
        return self.name

    def _get_docstring(self, node):
        docstring = ast.get_docstring(node)
        if docstring:
            docstring = self.parent.get_groups_and_flows(docstring)
        return docstring

    def get_groups_and_flows(self, docstring):
        docstring = self.parent.get_groups_and_flows(docstring)
        return docstring


class Class(PyObjectBase):

    def __init__(self, node, parent):
        super(Class, self).__init__(node, parent)
        self.methods = self.get_methods(node.body)

    def get_methods(self, nodes):
        return [ClassMethod(node, self) for node in nodes if isinstance(node, ast.FunctionDef)]


class ClassMethod(PyObjectBase):
    pass


class Function(PyObjectBase):
    pass


class Flow:

    def __init__(self, description, item):
        self.description = description
        self.id = item
        self.check_id()

    def check_id(self):
        raise NotImplementedError

    def __repr__(self):
        raise NotImplementedError


class Group(Flow):

    def __init__(self, description, item):
        super(Group, self).__init__(description, item)
        self.flow_defs = []

    def check_id(self):
        if isinstance(self.id, list):
            return True
        else:
            raise TypeError('Group ids must be list!')

    def __repr__(self):
        return self.description


class FlowDef(Flow):

    def __init__(self, description, item):
        super(FlowDef, self).__init__(description, item)
        self.flow_boxes = []

    def check_id(self):
        if isinstance(self.id, int):
            return True
        else:
            raise TypeError('Flow id must be integer!')

    def __repr__(self):
        return f'{self.id} {self.description}'


class FlowBox(Flow):

    def __init__(self, description, item, number, relations_str, decision):
        super(FlowBox, self).__init__(description, item)
        self.number = number
        self.relations_str = relations_str
        self.relations = []
        self.decision = decision

    def check_id(self):
        if isinstance(self.id, int):
            return True
        else:
            raise TypeError('Flow id must be integer!')

    def __repr__(self):
        return f'{self.id}-{self.number}'

