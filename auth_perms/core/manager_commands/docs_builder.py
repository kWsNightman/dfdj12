import ast
import re
import os
import datetime
import io
import argparse

from pygit2 import Repository

RE_PATH = r'\- \[.+\]\((.+)\).*'
RE_DEV = r'-\s(.+):\s\d+\.*\d*%'

dt = datetime.datetime.now()
now_dt = dt.strftime("%F")


def build_docs_service(service_path, service_name):
    """
    Main method docs_builder view
    Initialize scanner class and creating docs : main file and other doc files
    :param service_path: path where service project
    :param service_name: name service project
    :param branch: active repo
    :return: list created files
    """
    list_files = []

    data_files = DocsScannerPerformer(service_path)
    files_tree = generate_file_tree(service_path)
    child_docs = DocsGenerator(service_path, service_name, data_files.get_dict_order_by_path(service_path))
    main_doc = MainDocGenerator(service_path, service_name, files_tree, 'README')

    list_files.append(child_docs)
    list_files.append(main_doc)

    return list_files


def get_git_branch(service_path):
    repo = Repository(service_path)
    branch = repo.head.name.split('/')[-1]

    return branch


def remove_files(docs_paths):
    """
    Remove docs in local paths
    :param docs_paths: list docs
    :return: list removed files
    """
    removed_files = list()
    for path in docs_paths:
        try:
            os.remove(path)
            removed_files.append(path)
        except (FileNotFoundError, PermissionError):
            continue

    return removed_files


def generate_file_tree(path):
    ignore_files = ['wsgi.py', '__init__.py']
    file_name = os.path.basename(path)

    if file_name not in ignore_files:
        if file_name.rsplit('.', 1)[-1] == 'py' or file_name.rsplit('.', 1)[-1] == file_name:
            d = {'name': file_name}

            if os.path.isdir(path):
                d['type'] = "directory"
                list_files = [generate_file_tree(os.path.join(path, x)) for x in os.listdir(path)]
                list_files = [i for i in list_files if i is not None]
                list_files = [item for item in list_files
                              if item['type'] == 'directory' and item.get('children') or item['type'] == 'file']
                list_files.sort(key=lambda x: (x['type'], x['name']), reverse=False)

                d['children'] = list_files
            else:
                d['path'] = path
                d['type'] = "file"
            return d


class DocsScannerPerformer:
    """
    Return list with modules data
    """

    def __init__(self, path):
        """
        Main constructor Docs object
        :param path:
        """
        self.main_data = self.create_file_data(path)

    def get_dict_order_by_path(self, path):
        """
        Getting dict where group by path. Example:{'//home/':[],'//home/core':[]}
        :param path:
        :return: dict with lists modules.
        """
        list_modules = {}
        for module in self.main_data:
            try:
                key_path = str(module['Path']).replace(path, '')
                list_modules[key_path] = list()
            except TypeError:
                continue

        for module in self.main_data:
            try:
                key_path = str(module['Path']).replace(path, '')
                list_modules[key_path].append(module)
            except TypeError:
                continue

        return list_modules

    def create_file_data(self, service_path):
        """
        Group by searched docstrings. NOT USING. Also get_dict_order_by_path
        :param service_path:
        :return: list with modules data
        """

        ignore_files = ['.control', 'venv', 'configs', '.git', '__pycache__', 'env',
                        '.idea', 'docs', 'migrations', 'data_migrations', service_path.split('/', -1)[-1]]
        file_data = []
        if os.path.isdir(service_path):
            for path, dirs, files in os.walk(service_path, topdown=True):
                dirs[:] = [d for d in dirs if d not in ignore_files]
                data = self.find_modules(path)

                if data['modules']:
                    for module in data['modules']:
                        if module != '__init__.py' and module != 'wsgi.py':
                            value = {
                                "Module": module,
                                "Path": path,
                                "Data": data['modules'][module]
                            }
                            file_data.append(value)
            return file_data

    def find_modules(self, path):
        """
        Find files with prefix in catalog.
        :param path:
        :return: dict files
        """
        modules = dict()
        modules['modules'] = {}
        list_dir = os.listdir(path)
        for file in list_dir:

            file_path = os.path.join(path, file)

            if file_path.rsplit('.', 1)[-1] == 'py':
                modules['modules'][file] = self.get_docstring_module(file_path)
        return modules

    def get_docstring_module(self, path):
        """
        Getting all docstrings in files
        :param path:
        :return: dict docstrings
        """
        docstrings = {}
        list_classes = []
        with open(path) as file:
            file_module = ast.parse(file.read())

            docstrings['description'] = ast.get_docstring(file_module)
            if docstrings['description'] is not None:
                docstrings['description'] = docstrings['description'].replace('\n', ' ')

            class_definitions = [node for node in file_module.body if isinstance(node, ast.ClassDef)]

            for class_def in class_definitions:

                class_methods = self.get_docstring_from_list_methods(
                    [node for node in class_def.body if isinstance(node, ast.FunctionDef)])
                class_info = ast.get_docstring(class_def)

                if class_info is None:
                    class_info = ''
                else:
                    class_info = self.get_param(class_info)[2]

                if class_methods:
                    data_class = {
                        'name': class_def.name,
                        'description': class_info,
                        'methods': class_methods
                    }
                else:
                    data_class = {
                        'name': class_def.name,
                        'description': class_info,
                        'methods': {}
                    }

                list_classes.append(data_class)

            method_definitions = self.get_docstring_from_list_methods(
                [node for node in file_module.body if isinstance(node, ast.FunctionDef)])

            if method_definitions:
                docstrings['module_methods'] = method_definitions
            else:
                docstrings['module_methods'] = {}

            docstrings['module_classes'] = list_classes

        return docstrings

    def get_docstring_from_list_methods(self, list_methods):
        """
        Getting all docstrings in files
        :param list_methods:
        :return: dict docstrings
        """

        data_methods = {}
        for current_module in list_methods:
            try:
                list_args = {}
                name = current_module.name

                current_docstring = ast.get_docstring(current_module)
                arguments = [a.arg for a in current_module.args.args]

                params, returns, description = self.get_param(current_docstring)

                if description is not None:
                    description = description.replace('\n', ' ')

                list_args['Arguments'] = arguments
                list_args['Description'] = description
                list_args['Params'] = params
                for item in returns:
                    list_args['Return'] = str(item)
                data_methods[name] = list_args

            except (AttributeError, TypeError):
                name = current_module.name
                data_methods[name] = {
                    'Arguments': '',
                    'Description': '',
                    'Params': '',
                    'Return': ''
                }
                continue

        return data_methods

    @staticmethod
    def get_param(text):
        """
        Return list parameters searched by in docstrings.
        :param text: string docstring
        :return: list params, list returns and string description
        """
        params = []
        returns = []
        description = ''
        docstrings = text.split('\n')
        for line in docstrings:
            param_str = re.search(':param' + '(.*)$', line)
            if not param_str:
                param_str = re.search(':param:' + '(.*)$', line)

            return_str = re.search(':return:' + '(.*)$', line)
            if not return_str:
                return_str = re.search(':return' + '(.*)$', line)

            g_flows_str = re.search(':group:' + '(.*)$', line)
            if not g_flows_str:
                g_flows_str = re.search(':group' + '(.*)$', line)

            flow_str = re.search(':flow:' + '(.*)$', line)
            if not flow_str:
                flow_str = re.search(':flow' + '(.*)$', line)

            if param_str:
                params.append(param_str.group(1))
                continue
            if return_str:
                returns.append(return_str.group(1))
                continue
            if not flow_str and not g_flows_str:
                line = line.replace(' ', '&nbsp;')
                description += '{}{} <br>'.format('&nbsp;' * 4, line)

        return params, returns, description


class DocTemplate:
    """
    Formation of documents to template and also contains methods print, update files
    """

    def __init__(self):
        """
        Init with 'Sections'
        tags: html tags
        description: short description module
        modules: description methods and classes in module
        """
        self.name = ''
        self.path = ''
        self.tags = list()
        self.description = list()
        self.modules = list()

    def set_tags(self):
        """
        HTML tags for inserting chunks of text into a file
        :return: list tags
        """
        self.tags.append('<span id="Description">\n')
        self.tags.append('<span id="Modules">\n')
        self.tags.append('</span>\n')

    def set_description(self, branch, service_name, catalog_key):
        """
        Forming module short description
        :param branch: service repo branch
        :param service_name: service name in database
        :param catalog_key: path current module
        :return: list description
        """
        self.description.append('# Short description\n')
        self.description.append('| Properties | Data |')
        self.description.append('| ------------- | ------------- |')
        self.description.append('|**Branch:**| {}|'.format(branch))
        self.description.append('|**Service name:**| {}|'.format(service_name))
        self.description.append('|**Modules path:**| {}|'.format(catalog_key))
        self.description.append('|**Date of creation:**| {}|'.format(now_dt))
        self.description.append('|**Date of update:**| {}|\n'.format(now_dt))

    def set_doc_module(self, module_data):
        """
        Fills the section modules with data
        :param module_data: data received from the scanner
        :return: list modules
        """
        if module_data['module_classes']:
            for class_data in module_data['module_classes']:

                self.modules.append('*class* **{}**: <br>'.format(class_data['name']))

                if class_data['description']:
                    self.modules.append('{}'.format(class_data['description']))

                if class_data['methods']:
                    self.modules.append('* ***Methods:***')
                    self.modules.append('')
                    for method_name, method_data in class_data['methods'].items():

                        if method_data is not None:
                            method_arguments = ', '.join(item for item in method_data['Arguments']
                                                         if item != 'self')

                            try:
                                method_return = method_data['Return']
                            except KeyError:
                                method_return = ''

                            method_data = {
                                'name': method_name,
                                'arguments': method_arguments,
                                'description': method_data['Description'],
                                'params': method_data['Params'],
                                'return': method_return
                            }
                            self.modules.append('    **{}**({}):'.format(method_data['name'], method_data['arguments']))
                            if method_data['description']:
                                self.modules.append('    * ***Description***: <br>')
                                self.modules.append('        {}'.format(method_data['description']))

                            if method_data['params']:
                                self.modules.append('    * ***Parameters***: <br>')
                                for param in method_data['params']:
                                    self.modules.append('        * {}'.format(param))

                            if method_data['return']:
                                self.modules.append('    * ***Returns***: <br>')
                                self.modules.append('        * {}'.format(method_data['return']))
                            self.modules.append('')
                        else:
                            self.modules.append('{}'.format(method_name))

                self.modules.append('')

        if module_data['module_methods']:

            for method_name, method_data in module_data['module_methods'].items():

                if method_data is not None:
                    method_arguments = ', '.join(item for item in method_data['Arguments']
                                                 if item != 'self')
                    self.modules.append('\n')
                    self.modules.append('*function* **{}**({}):'.format(method_name, method_arguments))
                    for arg in method_data:
                        if method_data[arg] and arg != 'Arguments':
                            self.modules.append('  + **{}**: <br>'.format(arg))
                            if type(method_data[arg]) is list:
                                for item in method_data[arg]:
                                    if item:
                                        self.modules.append('    + {}'.format(item))
                            else:
                                if arg == 'Description':
                                    self.modules.append('{}'.format(method_data[arg]))
                                else:
                                    self.modules.append('{}{} <br>'.format('&nbsp;' * 4, method_data[arg]))
                else:
                    self.modules.append('+ {}'.format(method_name))

            self.modules.append('')

    def print_file(self):
        """
        Print generated file in local machine
        :return: path saved file
        """
        file_path = os.path.abspath(os.path.join(self.path, '{}.md'.format(self.name)))

        content = self.tags[0] + '\n' + '\n'.join(self.description) + self.tags[2] + '\n'
        content = content + self.tags[1] + '\n' + ' \n'.join(self.modules) + self.tags[2] + '\n'

        file_obj = open(file_path, 'wt')
        file_obj.write(content)
        file_obj.close()

        return file_path

    def update_file(self):
        """
        Update generated file in local machine
        :return: path updated file
        """
        file_path = os.path.abspath(os.path.join(self.path, '{}.md'.format(self.name)))

        tmp_file = io.StringIO()
        flag = False

        with open(file_path, 'rt') as r_file:
            for line in r_file:

                if '**Branch:**' in line:
                    tmp_file.write('{}'.format(self.description[3]))
                    tmp_file.write('\n')
                    continue

                if '**Service name:**' in line:
                    tmp_file.write('{}'.format(self.description[4]))
                    tmp_file.write('\n')
                    continue

                if '**Modules path:**' in line:
                    tmp_file.write('{}'.format(self.description[5]))
                    tmp_file.write('\n')
                    continue

                if '**Date of update:**' in line:
                    tmp_file.write('{}'.format(self.description[7]))
                    continue

                if not flag and '<span id="Modules">' in line:
                    tmp_file.write('<span id="Modules">\n')
                    tmp_file.write('\n')
                    content = '\n'.join(self.modules)
                    tmp_file.write(''.join(content))
                    flag = True
                    continue

                if flag and '</span>' in line:
                    tmp_file.write('</span>\n')
                    flag = False
                    continue

                if not flag:
                    tmp_file.write(line)

        with open(file_path, 'wt') as w_file:
            w_file.write(tmp_file.getvalue())
        tmp_file.close()

        return file_path


class DocsGenerator:
    """
    Base doc generator to template
    Return list created files
    """

    def __init__(self, service_path, service_name, data):
        self.list_files = self.generate_files(service_path, service_name, data)

    @staticmethod
    def generate_files(service_path, service_name, data):
        """
        Generate docs to template
        :param service_path: path to service in local machine
        :param service_name:
        :param data: data with description modules
        :param branch: active repo branch
        :return: list generated files
        """
        saved_files = []

        for catalog_key in data:
            save_file = DocTemplate()
            save_file.set_tags()
            save_file.set_description(get_git_branch(service_path), service_name, catalog_key)

            save_file.modules.append('# Modules description\n')

            for module in data[catalog_key]:
                module_name = module['Module']
                module_data = module['Data']
                module_path = module['Path']

                save_file.modules.append('## Module ' + module_name + '\n')

                if module_data.get('description') is not None:
                    save_file.modules.append('{}\n'.format(module_data.get('description')))

                save_file.set_doc_module(module_data)
                save_file.path = module_path

            save_file.name = save_file.path.rsplit("/", 1)[-1]
            save_file.path = service_path + '/docs' + save_file.path.replace(service_path, '')
            os.makedirs(save_file.path, exist_ok=True)

            if os.path.isfile(save_file.path + ('/{}.md'.format(save_file.name))):
                saved_files.append(save_file.update_file())
            else:
                saved_files.append(save_file.print_file())

        return saved_files


class MainDocGenerator:
    """
    Base main doc generator
    (Do not have template)
    """

    def __init__(self, service_path, service_name, tree, filename, save_file=None):
        """
        Run generate file method
        :param service_path:
        :param service_name:
        :param tree:
        :param filename: filename this file
        :param save_file:
        """
        if save_file is None:
            save_file = list()

        self.save_file = save_file
        self.list_files = self.generate_file(service_path, service_name, tree, filename)

    def generate_file(self, service_path, service_name, tree, filename):
        """
        Forming and print or update main file
        :param service_path:
        :param service_name:
        :param tree:
        :param filename:
        :return: path to saved file
        """

        if os.path.isdir(service_path):
            self.save_file.clear()
            self.save_file.append('\n## Directory structure of {} service:\n\n'.format(service_name))
            self.generate_file_data_from_tree(tree, service_path, [' '])

            content = ''.join(self.save_file)

            if os.path.isfile(service_path + ('/{}.md'.format(filename))):
                saved_file = self.update_file(service_path, content, filename)
            else:
                saved_file = self.print_file(service_path, content, filename)

            return saved_file
        else:
            return None

    def generate_file_data_from_tree(self, tree, service_path, tabs, node=0, fixed_node=None, last_file=None):
        """
        Recursive walk on tree. Forming data in list format for print file.
        :param tree:
        :param service_path:
        :param tabs:
        :param node:
        :param fixed_node:
        :param last_file:
        :return: None
        """
        file_name = tree.get('name')
        file_type = tree.get('type')
        file_path = tree.get('path')
        file_nodes = tree.get('children')

        if fixed_node is None:
            fixed_node = list()

        if last_file is None:
            last_file = dict()

        if file_name != service_path.rsplit('/', 1)[-1]:
            print_tabs = ''

            if fixed_node:
                for f_node in fixed_node:
                    if f_node < node - 1:
                        try:
                            tabs[f_node] += '│'
                        except IndexError:
                            break

            for space in tabs:
                print_tabs += '{}'.format(space)

            tabs = [' ']

            if file_type == 'directory':
                self.save_file.append('{}**{}** <br>'.format(print_tabs, file_name))

            elif file_type == 'file':
                catalog_name = file_path.rsplit("/", 1)[0]
                doc_ref = catalog_name + '/{}.md'.format(catalog_name.rsplit("/", 1)[1])
                doc_ref = doc_ref.replace(service_path, '/docs')

                if last_file['name'] == file_name:
                    print_tabs = print_tabs.replace('├', '└')

                self.save_file.append('{}[***{}***]({}#module-{}) <br>'.format(print_tabs, file_name, doc_ref,
                                                                               file_name.replace('.', '')))

        if file_type == 'directory':

            last_file = file_nodes[-1]
            for x in file_nodes:

                if len(tree['children']) > 1:
                    if node not in fixed_node:
                        fixed_node.append(node)

                if x == last_file:
                    fixed_node = [l_node for l_node in fixed_node if l_node is not node]
                    type_symbol = '└'
                else:
                    type_symbol = '├'

                for i in range(node + 1):
                    try:
                        tabs[i] = '{}'.format(('&nbsp;' * 4))
                    except IndexError:
                        tabs.insert(i, '{}'.format(('&nbsp;' * 4)))

                tabs.append(type_symbol)
                self.generate_file_data_from_tree(x, service_path, tabs, node + 1, fixed_node, last_file)
                tabs = [' ']

    @staticmethod
    def print_file(file_path, data, filename):
        """
        Print main file
        :param file_path: path to main file
        :param data: data main file
        :param filename: name this file
        :return: path saved file
        """

        doc_name = filename
        file_path = os.path.abspath(os.path.join(file_path, '{}.md'.format(doc_name)))

        content = '<span id="Service_modules">\n' + data + '\n</span>\n'

        file_obj = open(file_path, 'wt')
        file_obj.write(content)
        file_obj.close()

        return file_path

    @staticmethod
    def update_file(file_path, data, filename):
        """
        Update main file
        :param file_path: path to main file
        :param data: data main file
        :param filename: name this file
        :return: path saved file
        """

        doc_name = filename
        file_path = os.path.abspath(os.path.join(file_path, '{}.md'.format(doc_name)))

        tmp_file = io.StringIO()
        flag = False
        main_section = False
        with open(file_path, 'rt') as r_file:
            for line in r_file:

                if not flag and '<span id="Service_modules">' in line:
                    tmp_file.write('<span id="Service_modules">\n')
                    tmp_file.write(''.join(data))
                    flag = True
                    main_section = True
                    continue

                if flag and '</span>' in line:
                    tmp_file.write('\n</span>\n')
                    flag = False
                    continue

                if not flag:
                    tmp_file.write(line)

            if not main_section:
                tmp_file.write('\n')
                tmp_file.write('<span id="Service_modules">\n')
                tmp_file.write('\n')
                tmp_file.write(''.join(data))
                tmp_file.write('\n</span>\n')

        with open(file_path, 'wt') as w_file:
            w_file.write(tmp_file.getvalue())
        tmp_file.close()

        return file_path
