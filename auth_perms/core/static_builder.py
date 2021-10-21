from os import listdir
from os.path import isfile, join
from flask import url_for


class StaticBuilder():

    def __init__(
        self,
        js_folder_path: str = "",
        libs_names: list = [],
        css_folder_path: str = "",
        part_creators: list = [],
        variable_creators: list = [],
        **variables
    ):
        self.variables = variables
        self.js_folder_path = js_folder_path
        self.css_folder_path = css_folder_path
        self.js_file = ""
        self.css_file = ""
        self.part_creators = part_creators
        self.variable_creators = variable_creators
        self.libs_names = libs_names
        self.libs = []

    def append_part_creators(self, *args):
        self.part_creators += list(args)

    def append_variable_creators(self, *args):
        self.variable_creators += list(args)

    def build(self):
        self._read_js_file()
        self._read_js_libraries()
        self._build_css()
        self._build_js()
        return dict(
            js=self.js_file,
            css=self.css_file
        )

    def _build_js(self):
        self._initialize_fragments()
        self._append_js_libraries()
        self._build_script()

    def _initialize_fragments(self):
        parts = self._create_fragments(self.part_creators)
        self.variables.update(
            *self._create_fragments(self.variable_creators)
        )
        self._insert_variables()
        self._append_parts(parts)

    def _read_js_libraries(self):
        with open(self.js_folder_path + 'auth.js', "r") as file:
            self.js_file = file.read()

    def _read_js_file(self):
        for lib_name in self.libs_names:
            with open(self.js_folder_path + lib_name, "r") as file:
                self.libs.append(file.read())

    def _build_css(self):
        self.css_file = str()
        for f in listdir(self.css_folder_path):
            if isfile(join(self.css_folder_path, f)):
                self.css_file += """<link href="{}" rel="stylesheet">\n"""\
                    .format(
                        url_for(
                            'auth_submodule.static',
                            filename='css/' + f
                        )
                    )

    def _insert_variables(self):
        self.js_file = self.js_file % self.variables

    def _append_parts(self, parts):
        for part in parts:
            self.js_file += "\n" + part

    def _append_js_libraries(self):
        for lib in self.libs:
            self.js_file = lib + '\n' + self.js_file

    def _create_fragments(self, creators: list = []):
        fragments = list()
        for creator in creators:
            fragments.append(
                creator(
                    **self.variables
                )
            )
        return fragments

    def _build_script(self):
        self.js_file = """<script>{}</script>\n"""\
            .format(self.js_file)
