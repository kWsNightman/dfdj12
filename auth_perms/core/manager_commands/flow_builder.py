import ast
import re
import os
import io
import tokenize

from pygit2 import Repository
from collections import Counter

COMMENT_RE = re.compile(r'^(\s*)#\s?(.*)$')


def service_flows(service_path, service_name, filename):
    flows_obj = FlowScannerPerformer(service_path)
    flows_list = flows_obj.flows_list
    flows_groups = flows_obj.groups_list

    flows_dict_list, groups_dict_list = create_dict_flows(flows_list, flows_groups)

    f_list_html_urls = generate_flows_list(service_path, flows_dict_list, groups_dict_list, True)
    f_list = generate_flows_list(service_path, flows_dict_list, groups_dict_list, False)

    flows_file_obj = FlowSaverPerformer(service_path, service_name, f_list_html_urls, filename)

    return f_list


def get_git_url(service_path):
    repo = Repository(service_path)
    branch = repo.head.name.split('/')[-1]
    remote_url = repo.remotes['origin'].url

    # Check if remote url is ssh
    remote_url = ssh_to_https(remote_url)

    href = f'{remote_url}/blob/{branch}'

    return href


def ssh_to_https(remote_url):
    if remote_url[:3] == 'ssh':
        remote_url = 'https://' + remote_url[remote_url.index('@') + 1:]
        remote_url = re.sub(r':\d{1,5}', '', remote_url)

    remote_url = remote_url.replace('.git', '')

    return remote_url


def get_submodules(service_path):
    result = []
    repo = Repository(service_path)
    submodules = repo.listall_submodules()

    for subm in submodules:
        subm_repo = Repository(subm)
        result.append({
            'https_url': ssh_to_https(subm_repo.remotes['origin'].url),
            'path': subm,
            'last_commit': str(subm_repo.head.target)
        })

    return result


def generate_flows_list(service_path, flows, g_flows, html_urls=False):
    list_flows_obj = list()

    g_flows.sort(key=lambda x: (x['name']), reverse=False)
    for group in g_flows:
        fg_obj = {'name': group.get('name'), 'submodule': ''}
        list_flows = list()
        list_submodules = list()
        r_relations = list()

        group_path = group.get('path')
        list_flows.append('graph TD\n')
        for g_flow in group.get('flows'):
            try:
                flow_obj = next((flow for flow in flows if flow["flow_id"] == g_flow
                                 and flow["flow_path"].startswith(group_path)))
            except (StopIteration, KeyError):
                continue

            list_flows.append('subgraph {}\n'.format(flow_obj.get('flow_name')))
            boxes = flow_obj['flow_boxes']
            for step_obj in boxes:
                href_submodule = None
                for submodule in get_submodules(service_path):
                    if step_obj.get('box_href').find(submodule.get('path')) >= 0:
                        href_submodule = submodule.get('https_url') + \
                                         step_obj.get('box_href').replace(submodule.get('path'), 'blob/' +
                                                                          submodule.get('last_commit'), 1)
                        break

                if href_submodule:
                    sub_name = href_submodule.split('/')
                    list_submodules.append(sub_name[4])
                    href = href_submodule
                else:
                    href = get_git_url(service_path) + step_obj.get('box_href')

                if html_urls:
                    if step_obj.get('box_decision'):

                        list_flows.append('{}'.format(flow_obj['flow_id'] + step_obj["box_id"]) + '{' +
                                          "<a href='{}'>{}</a>".format(href, step_obj.get('box_name')) + '}\n')
                    else:
                        list_flows.append("{}[<a href='{}'>{}</a>]\n".format(flow_obj['flow_id'] + step_obj["box_id"],
                                                                             href,
                                                                             step_obj.get('box_name')))
                else:
                    if step_obj.get('box_decision'):
                        list_flows.append('{}'.format(flow_obj['flow_id'] + step_obj["box_id"]) + '{' +
                                          "{}".format(step_obj.get('box_name')) + '}\n')
                    else:
                        list_flows.append('{}["{}"]\n'.format(flow_obj['flow_id'] + step_obj["box_id"],
                                                              step_obj.get('box_name')))

                if step_obj.get('box_relations'):
                    step_relations = step_obj.get('box_relations').split(',')
                    for s_rel in step_relations:
                        text_arrow = re.search('\|(.*)\|', s_rel)
                        if text_arrow:
                            text_arrow = text_arrow.group(0)
                            s_rel = s_rel.replace(text_arrow, '')
                            s_rel = s_rel.split('-')

                            s_rel_name = s_rel[0] + s_rel[1]

                            r_relations.append('{}-->{}{}\n'.format(flow_obj['flow_id'] + step_obj["box_id"],
                                                                    text_arrow, s_rel_name))
                        else:
                            s_rel = s_rel.split('-')
                            s_rel_name = s_rel[0] + s_rel[1]

                            r_relations.append('{}-->{}\n'.format(flow_obj['flow_id'] + step_obj["box_id"],
                                                                  s_rel_name))
            list_flows.append('end\n')

        list_flows += r_relations

        fg_obj['flows'] = list_flows

        if list_submodules:
            count_subs = Counter(list_submodules)
            submodule = count_subs.most_common(1)[0]

            if submodule:
                fg_obj['submodule'] = submodule[0]

        list_flows_obj.append(fg_obj)

    return list_flows_obj


def create_dict_flows(flows, g_flows):
    if flows:
        flows.sort()

    flows_list = list()
    g_list = []

    for flow in flows:

        flow_decision = False
        if flow.find('?') >= 0:
            flow = flow.replace('?', '')
            flow_decision = True

        flow_str = re.search('"(.*)"', flow)
        flow_path = re.search('%%(.*)%%', flow)
        flow = flow.replace(flow_path.group(0), '')

        flow_href = flow_path.group(1)
        flow_path = flow_path.group(1).replace(os.path.basename(flow_path.group(1)), '')

        if not flow_str:
            flow_str = re.search('"(.*)"', '""')

        flow_id = (flow.replace(flow_str.group(0), '')).replace(' ', '')
        flow_relations = re.search('\((.*)\)', flow_id)

        if flow_relations:
            flow_id = flow_id.replace(flow_relations.group(0), '')
            flow_relations = flow_relations.group(1)

        flow_id = flow_id.split('-')
        flow_desc = flow_str.group(1)

        if len(flow_id) == 1:
            flow_obj = {
                'flow_id': flow_id[0],
                'flow_name': flow_desc,
                'flow_path': flow_path,
                'flow_href': flow_href,
                'flow_boxes': []
            }
            flows_list.append(flow_obj)
        elif len(flow_id) == 2:
            try:
                flow_obj = next((flow for flow in flows_list if flow["flow_id"] == flow_id[0]
                                 and flow["flow_path"] == flow_path), False)
            except (StopIteration, KeyError):
                continue

            if flow_obj:
                box_obj = {
                    'box_id': flow_id[1],
                    'box_name': flow_desc,
                    'box_decision': flow_decision,
                    'box_href': flow_href,
                    'box_relations': flow_relations
                }

                flow_obj['flow_boxes'].append(box_obj)

    for group in g_flows:
        group_path = re.search('%%(.*)%%', group)
        group = group.replace(group_path.group(0), '')

        group_path = group_path.group(1).replace(os.path.basename(group_path.group(1)), '')
        group_name = re.search('"(.*)"', group)

        if not group_name:
            group_name = re.search('"(.*)"', '""')

        group_list = (group.replace(group_name.group(0), '')).replace(' ', '')
        group_list = re.search('\((.*)\)', group_list)
        group_list = group_list.group(1).split(',')

        if group_name:
            g_list.append({
                'name': group_name.group(1),
                'path': group_path,
                'flows': group_list
            })

    return flows_list, g_list


class FlowScannerPerformer:
    def __init__(self, path):
        self.flows_list, self.groups_list = self.create_object(path)

    def create_object(self, service_path):
        ignore_files = ['.control', 'venv', 'configs', '.git', '__pycache__', 'env',
                        '.idea', 'docs', 'migrations', 'data_migrations', service_path.split('/', -1)[-1]]
        flows_list = list()
        groups_list = list()
        if os.path.isdir(service_path):
            for path, dirs, files in os.walk(service_path, topdown=True):
                dirs[:] = [d for d in dirs if d not in ignore_files]
                flows, groups = self.find_flows(path, service_path)
                if flows:
                    flows_list += flows
                if groups:
                    groups_list += groups

        return flows_list, groups_list

    def find_flows(self, path, service_path):
        flows_list = list()
        groups_list = list()
        list_dir = os.listdir(path)
        for file in list_dir:

            file_path = os.path.join(path, file)

            if file_path.rsplit('.', 1)[-1] == 'py':
                flows, groups = self.get_flows_list(file_path, service_path)
                if flows:
                    flows_list += flows
                if groups:
                    groups_list += groups
        return flows_list, groups_list

    def get_flows_list(self, path, service_path):
        flows_list = list()
        groups_list = list()
        flows_list += self.get_flows_from_comments_in_file(path, service_path)

        with open(path) as file:
            file_module = ast.parse(file.read())
            class_definitions = [node for node in file_module.body if isinstance(node, ast.ClassDef)]

            for class_def in class_definitions:

                flows_class_methods, f_groups_class_methods = self.get_flows_from_list_methods(
                    [node for node in class_def.body if isinstance(node, ast.FunctionDef)], path, service_path)

                if flows_class_methods:
                    flows_list += flows_class_methods
                if f_groups_class_methods:
                    groups_list += f_groups_class_methods

                class_description = ast.get_docstring(class_def)

                if class_description:
                    f_class, g_class = self.get_flow_str(class_description)
                    if f_class:
                        flows_list += [f + ' %%{}#L{}%%'.format(path.replace(service_path, ''),
                                                                str(class_def.lineno)) for f in f_class]
                    if g_class:
                        groups_list += [g + ' %%{}#L{}%%'.format(path.replace(service_path, ''),
                                                                 str(class_def.lineno)) for g in g_class]

            flows_methods, f_groups_methods = self.get_flows_from_list_methods(
                [node for node in file_module.body if isinstance(node, ast.FunctionDef)], path, service_path)

            if flows_methods:
                flows_list += flows_methods
            if f_groups_methods:
                groups_list += f_groups_methods

        return flows_list, groups_list

    def get_flows_from_list_methods(self, list_methods, path, service_path):
        flows_list = list()
        group_list = list()
        for current_module in list_methods:
            try:
                current_docstring = ast.get_docstring(current_module)
                flows, f_groups = self.get_flow_str(current_docstring)
                if flows:
                    flows_list += [f + ' %%{}#L{}%%'.format(path.replace(service_path, ''),
                                                            str(current_module.lineno)) for f in flows]
                if f_groups:
                    group_list += [g + ' %%{}#L{}%%'.format(path.replace(service_path, ''),
                                                            str(current_module.lineno)) for g in f_groups]
            except (AttributeError, TypeError):
                continue

        return flows_list, group_list

    @staticmethod
    def get_flows_from_comments_in_file(path, service_path):
        flows_list = list()
        with open(path) as file:
            for toktype, tokval, begin, end, line in tokenize.generate_tokens(file.readline):
                match = COMMENT_RE.match(tokval)
                if match:
                    try:
                        flow_str = re.search(':flow:' + '(.*)$', match.group(0))
                        if not flow_str:
                            flow_str = re.search(':flow' + '(.*)$', match.group(0))

                        if flow_str:
                            flow_str = flow_str.group(1)
                            flow_str += ' %%{}#L{}%%'.format(path.replace(service_path, '', 1), begin[0])
                            flows_list.append(flow_str)

                    except (AttributeError, TypeError):
                        continue
        return flows_list

    @staticmethod
    def get_flow_str(docstring):

        str_doc = docstring.split('\n')
        flows_list = list()
        group_list = list()
        for item in str_doc:

            g_flows_str = re.search(':group:' + '(.*)$', item)
            if not g_flows_str:
                g_flows_str = re.search(':group' + '(.*)$', item)

            flow_str = re.search(':flow:' + '(.*)$', item)
            if not flow_str:
                flow_str = re.search(':flow' + '(.*)$', item)

            if flow_str:
                flows_list.append(flow_str.group(1))
            elif g_flows_str:
                group_list.append(g_flows_str.group(1))
        return flows_list, group_list


class FlowSaverPerformer:
    """
    Base flow saver
    """

    def __init__(self, service_path, service_name, flows_list, filename):
        self.saved_file = self.generate_file(service_path, service_name, flows_list, filename)

    def generate_file(self, service_path, service_name, flows_list, filename):
        save_file = []
        group_name = ''
        if flows_list:
            flows_list.sort(key=lambda x: (x['submodule']), reverse=False)

            if os.path.isdir(service_path):
                save_file.clear()
                save_file.append('\n## FLOWS of {} service:\n\n'.format(service_name))
                for group in flows_list:

                    if group.get('submodule'):
                        if group_name != group.get('submodule'):
                            save_file.append('#### Submodule {} FLOW:\n'.format(group.get('submodule')))
                            group_name = group.get('submodule')

                        save_file.append('##### {}:\n'.format(group.get('name')))
                    else:
                        save_file.append('#### {}:\n'.format(group.get('name')))

                    save_file.append('```mermaid\n')
                    save_file += group.get('flows')
                    save_file.append('```\n')
                content = ''.join(save_file)

                if os.path.isfile(service_path + ('/{}.md'.format(filename))):
                    saved_file = self.update_file(service_path, content, filename)
                else:
                    saved_file = self.print_file(service_path, content, filename)

                return saved_file
            else:
                return None
        else:
            return None

    @staticmethod
    def print_file(file_path, data, filename):
        doc_name = filename
        file_path = os.path.abspath(os.path.join(file_path, '{}.md'.format(doc_name)))

        content = '<span id="Service_flows">\n' + data + '\n</span>\n'

        file_obj = open(file_path, 'wt')
        file_obj.write(content)
        file_obj.close()

        return file_path

    @staticmethod
    def update_file(file_path, data, filename):
        doc_name = filename
        file_path = os.path.abspath(os.path.join(file_path, '{}.md'.format(doc_name)))

        tmp_file = io.StringIO()
        flag = False
        main_section = False
        with open(file_path, 'rt') as r_file:
            for line in r_file:

                if not flag and '<span id="Service_flows">' in line:
                    tmp_file.write('<span id="Service_flows">\n')
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
                tmp_file.write('<span id="Service_flows">\n')
                tmp_file.write('\n')
                tmp_file.write(''.join(data))
                tmp_file.write('\n</span>\n')

        with open(file_path, 'wt') as w_file:
            w_file.write(tmp_file.getvalue())
        tmp_file.close()

        return file_path
